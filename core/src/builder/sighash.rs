//! # Sighash Builder
//!
//! Sighash builder provides useful functions for building related SigHashes.
//! Sighash is the message that is signed by the private key of the signer. It is used to signal
//! under which conditions the input is signed. See for more:
//! https://developer.bitcoin.org/devguide/transactions.html?highlight=sighash#signature-hash-types

use crate::builder::transaction::TxHandler;
use crate::config::BridgeConfig;
use crate::constants::NUM_INTERMEDIATE_STEPS;
use crate::errors::BridgeError;
use crate::{builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint, TapLeafHash, TapSighashType};
use bitcoin::{TapSighash, Txid, XOnlyPublicKey};
use futures_core::stream::Stream;

// WIP: For now, this is equal to the number of sighashes we yield in create_nofn_sighash_stream.
// This will change as we implement the system design.
pub fn calculate_num_required_sigs(config: &BridgeConfig) -> usize {
    config.num_operators
        * config.num_time_txs
        * config.num_kickoffs_per_timetx
        * (10 + 2 * config.num_watchtowers)
}

/// Generates the sighash for a given transaction input for key spend path.
pub fn convert_tx_to_pubkey_spend(
    tx_handler: &mut TxHandler,
    txin_index: usize,
    sighash_type: Option<TapSighashType>,
) -> Result<TapSighash, BridgeError> {
    let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
        SighashCache::new(&mut tx_handler.tx);
    let prevouts = &match sighash_type {
        Some(TapSighashType::SinglePlusAnyoneCanPay)
        | Some(TapSighashType::AllPlusAnyoneCanPay)
        | Some(TapSighashType::NonePlusAnyoneCanPay) => {
            bitcoin::sighash::Prevouts::One(txin_index, tx_handler.prevouts[txin_index].clone())
        }
        _ => bitcoin::sighash::Prevouts::All(&tx_handler.prevouts),
    };

    let sig_hash = sighash_cache.taproot_key_spend_signature_hash(
        txin_index,
        prevouts,
        sighash_type.unwrap_or(TapSighashType::Default),
    )?;

    Ok(sig_hash)
}

/// Generates the sighash for a given transaction input for script spend path.
#[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub fn convert_tx_to_script_spend(
    tx_handler: &mut TxHandler,
    txin_index: usize,
    script_index: usize,
    sighash_type: Option<TapSighashType>,
) -> Result<TapSighash, BridgeError> {
    let mut sighash_cache: SighashCache<&mut bitcoin::Transaction> =
        SighashCache::new(&mut tx_handler.tx);

    let prevouts = &match sighash_type {
        Some(TapSighashType::SinglePlusAnyoneCanPay)
        | Some(TapSighashType::AllPlusAnyoneCanPay)
        | Some(TapSighashType::NonePlusAnyoneCanPay) => {
            bitcoin::sighash::Prevouts::One(txin_index, tx_handler.prevouts[txin_index].clone())
        }
        _ => bitcoin::sighash::Prevouts::All(&tx_handler.prevouts),
    };
    let leaf_hash = TapLeafHash::from_script(
        tx_handler
            .prev_scripts
            .get(txin_index)
            .ok_or(BridgeError::NoScriptsForTxIn(txin_index))?
            .get(script_index)
            .ok_or(BridgeError::NoScriptAtIndex(script_index))?,
        LeafVersion::TapScript,
    );
    let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
        txin_index,
        prevouts,
        leaf_hash,
        sighash_type.unwrap_or(TapSighashType::Default),
    )?;

    Ok(sig_hash)
}

/// For a given deposit tx, for each operator and sequential_collateral tx, generates the SigHash stream for:
/// - challenge_tx,
/// - start_happy_reimburse_tx,
/// - happy_reimburse_tx,
/// -
/// -
/// Refer to bridge design diagram to see which NofN signatures are needed (the ones marked with blue arrows).
/// WIP: Update if the design changes.
pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    _evm_address: EVMAddress,
    _recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    _user_takes_after: u64,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    try_stream! {
        // Create move_tx handler. This is unique for each deposit tx.
        let move_txhandler = builder::transaction::create_move_txhandler(
            deposit_outpoint,
            _evm_address,
            &_recovery_taproot_address,
            nofn_xonly_pk,
            _user_takes_after as u32,
            bridge_amount_sats,
            network,
        );
        // Get operator details (for each operator, (X-Only Public Key, Address, Collateral Funding Txid))
        let operators: Vec<(XOnlyPublicKey, bitcoin::Address, Txid)> =
            db.get_operators(None).await?;
        if operators.len() < config.num_operators {
            panic!("Not enough operators");
        }

        // Get the X-Only Public Keys of all watchtowers. These are needed since they will be used inside the scripts.
        let watchtower_pks = db.get_all_watchtowers_xonly_pks(None).await?;

        for (operator_idx, (operator_xonly_pk, operator_reimburse_address, collateral_funding_txid)) in
            operators.iter().enumerate()
        {
            // Get watchtower Winternitz pubkeys for this operator.
            let watchtower_challenge_wotss = (0..config.num_watchtowers)
                .map(|i| db.get_watchtower_winternitz_public_keys(None, i as u32, operator_idx as u32))
                .collect::<Vec<_>>();
            let watchtower_challenge_wotss =
                futures::future::try_join_all(watchtower_challenge_wotss).await?;

            let mut input_txid = *collateral_funding_txid;
            let mut input_amount = collateral_funding_amount;

            for time_tx_idx in 0..config.num_time_txs {
                let sequential_collateral_txhandler = builder::transaction::create_sequential_collateral_txhandler(
                    *operator_xonly_pk,
                    input_txid,
                    input_amount,
                    timeout_block_count,
                    max_withdrawal_time_block_count,
                    config.num_kickoffs_per_timetx,
                    network,
                );

                let reimburse_generator_txhandler = builder::transaction::create_reimburse_generator_txhandler(
                    &sequential_collateral_txhandler,
                    *operator_xonly_pk,
                    config.num_kickoffs_per_timetx,
                    network,
                );

                // For each time_tx, we have multiple kickoff_utxos as the connectors (TODO: Maybe change later).
                // For each kickoff_utxo, it connnects to a kickoff_tx that results in
                // either start_happy_reimburse_tx
                // or challenge_tx, which forces the operator to initiate BitVM sequence (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
                for kickoff_idx in 0..config.num_kickoffs_per_timetx {
                    let kickoff_txhandler = builder::transaction::create_kickoff_txhandler(
                        &sequential_collateral_txhandler,
                        kickoff_idx,
                        nofn_xonly_pk,
                        *operator_xonly_pk,
                        move_txhandler.txid,
                        operator_idx,
                        network,
                    );

                    // Creates the challenge_tx handler.
                    let mut challenge_tx = builder::transaction::create_challenge_txhandler(
                        &kickoff_txhandler,
                        operator_reimburse_address,
                    );

                    // Creates the sighash for the challenge_tx.
                    yield convert_tx_to_pubkey_spend(
                        &mut challenge_tx,
                        0,
                        Some(bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
                    )?;

                    // Creates the start_happy_reimburse_tx handler.
                    let mut start_happy_reimburse_txhandler = builder::transaction::create_start_happy_reimburse_txhandler(
                        &kickoff_txhandler,
                        *operator_xonly_pk,
                        network
                    );

                    // Creates the sighash for the start_happy_reimburse_tx.
                    yield convert_tx_to_pubkey_spend(
                        &mut start_happy_reimburse_txhandler,
                        1,
                        None
                    )?;

                    // Creates the happy_reimburse_tx handler.
                    let mut happy_reimburse_txhandler = builder::transaction::create_happy_reimburse_txhandler(
                        &move_txhandler,
                        &start_happy_reimburse_txhandler,
                        &reimburse_generator_txhandler,
                        kickoff_idx,
                        operator_reimburse_address,
                    );

                    // Creates the sighash for the happy_reimburse_tx.
                    yield convert_tx_to_pubkey_spend(
                        &mut happy_reimburse_txhandler,
                        0,
                        None
                    )?;

                    //
                    let watchtower_wots = (0..config.num_watchtowers)
                        .map(|i| watchtower_challenge_wotss[i][time_tx_idx * config.num_kickoffs_per_timetx + kickoff_idx].clone())
                        .collect::<Vec<_>>();

                    let mut watchtower_challenge_kickoff_txhandler =
                        builder::transaction::create_watchtower_challenge_kickoff_txhandler(
                            &kickoff_txhandler,
                            config.num_watchtowers as u32,
                            &watchtower_pks,
                            watchtower_wots.clone(),
                            network,
                        );

                    yield convert_tx_to_pubkey_spend(
                        &mut watchtower_challenge_kickoff_txhandler,
                        0,
                        None,
                    )?;

                    let mut kickoff_timeout_txhandler = builder::transaction::create_kickoff_timeout_txhandler(
                        &kickoff_txhandler,
                        &sequential_collateral_txhandler,
                        network,
                    );

                    yield convert_tx_to_script_spend(
                        &mut kickoff_timeout_txhandler,
                        0,
                        0,
                        None,
                    )?;

                    for i in 0..config.num_watchtowers {
                        let watchtower_challenge_txhandler =
                            builder::transaction::create_watchtower_challenge_txhandler(
                                &watchtower_challenge_kickoff_txhandler,
                                i,
                                &[0u8; 20], // TODO: ozan real op unlock hash PUT THE HASHES OF THE PREIMAGES HERE
                                nofn_xonly_pk,
                                *operator_xonly_pk,
                                network,
                            );

                        let mut operator_challenge_nack_txhandler =
                            builder::transaction::create_operator_challenge_nack_txhandler(
                                &watchtower_challenge_txhandler,
                                &kickoff_txhandler
                            );
                        yield convert_tx_to_script_spend(
                            &mut operator_challenge_nack_txhandler,
                            0,
                            1,
                            None,
                        )?;
                        yield convert_tx_to_pubkey_spend(
                            &mut operator_challenge_nack_txhandler,
                            1,
                            None,
                        )?;
                    }

                    let intermediate_wots =
                        vec![vec![vec![[0u8; 20]; 48]; NUM_INTERMEDIATE_STEPS]; config.num_time_txs]; // TODO: Fetch from db
                    let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
                        &kickoff_txhandler,
                        nofn_xonly_pk,
                        intermediate_wots[time_tx_idx].clone(),
                        network,
                    );

                    let mut assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
                        &kickoff_txhandler,
                        &assert_begin_txhandler,
                        nofn_xonly_pk,
                        *operator_xonly_pk,
                        network,
                    );
                    yield convert_tx_to_pubkey_spend(
                        &mut assert_end_txhandler,
                        NUM_INTERMEDIATE_STEPS,
                        None,
                    )?;

                    let mut disprove_timeout_txhandler = builder::transaction::create_disprove_timeout_txhandler(
                        &assert_end_txhandler,
                        *operator_xonly_pk,
                        network,
                    );

                    // sign disprove scripts utxo
                    yield convert_tx_to_pubkey_spend(
                        &mut disprove_timeout_txhandler,
                        0,
                        None,
                    )?;

                    // sign nofn_1week disprove timeout utxo
                    yield convert_tx_to_script_spend(
                        &mut disprove_timeout_txhandler,
                        1,
                        0,
                        None,
                    )?;

                    let mut already_disproved_txhandler = builder::transaction::create_already_disproved_txhandler(
                        &assert_end_txhandler,
                        &sequential_collateral_txhandler,
                    );

                    // sign nofn_2week disprove timeout utxo
                    yield convert_tx_to_script_spend(
                        &mut already_disproved_txhandler,
                        0,
                        1,
                        None,
                    )?;

                    let mut reimburse_txhandler = builder::transaction::create_reimburse_txhandler(
                        &move_txhandler,
                        &disprove_timeout_txhandler,
                        &reimburse_generator_txhandler,
                        kickoff_idx,
                        operator_reimburse_address,
                    );

                    yield convert_tx_to_pubkey_spend(&mut reimburse_txhandler, 0, None)?;
                }

                input_txid = reimburse_generator_txhandler.txid;
                input_amount = reimburse_generator_txhandler.tx.output[0].value;
            }
        }
    }
}
