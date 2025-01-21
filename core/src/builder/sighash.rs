use crate::builder::transaction::TxHandler;
use crate::config::BridgeConfig;
use crate::constants::{NUM_INTERMEDIATE_STEPS, PARALLEL_ASSERT_TX_CHAIN_SIZE};
use crate::errors::BridgeError;
use crate::{builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint, TapLeafHash, TapSighashType};
use bitcoin::{TapSighash, Txid, XOnlyPublicKey};
use futures_core::stream::Stream;

// TODO: For now, this is equal to the number of sighashes we yield in create_nofn_sighash_stream.
// This will change as we implement the system design.
pub fn calculate_num_required_sigs(config: &BridgeConfig) -> usize {
    config.num_operators
        * config.num_time_txs
        * config.num_kickoffs_per_timetx
        * (10 + 2 * config.num_watchtowers)
}

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

/// Construct every deposit tx for each operator, sequential_collateral, and kickoff utxo,
/// and yield the sighash for each txin that needs a NofN signature.
/// Refer to bridge design diagram to see which NofN signatures are needed (the ones marked with blue arrows)
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
        let move_txhandler = builder::transaction::create_move_txhandler(
            deposit_outpoint,
            _evm_address,
            &_recovery_taproot_address,
            nofn_xonly_pk,
            _user_takes_after as u32,
            bridge_amount_sats,
            network,
        );

        let operators: Vec<(XOnlyPublicKey, bitcoin::Address, Txid)> =
            db.get_operators(None).await?;
        if operators.len() < config.num_operators {
            panic!("Not enough operators");
        }

        let watchtower_pks = db.get_all_watchtowers_xonly_pks(None).await?;

        for (operator_idx, (operator_xonly_pk, _operator_reimburse_address, collateral_funding_txid)) in
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

                    let mut challenge_tx = builder::transaction::create_challenge_txhandler(
                        &kickoff_txhandler,
                        _operator_reimburse_address,
                    );

                    yield convert_tx_to_pubkey_spend(
                        &mut challenge_tx,
                        0,
                        Some(bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
                    )?;

                    let mut start_happy_reimburse_txhandler = builder::transaction::create_start_happy_reimburse_txhandler(
                        &kickoff_txhandler,
                        *operator_xonly_pk,
                        network
                    );

                    // sign kickoff_tx utxo
                    yield convert_tx_to_pubkey_spend(
                        &mut start_happy_reimburse_txhandler,
                        1,
                        None
                    )?;

                    let mut happy_reimburse_txhandler = builder::transaction::create_happy_reimburse_txhandler(
                        &move_txhandler,
                        &start_happy_reimburse_txhandler,
                        &reimburse_generator_txhandler,
                        kickoff_idx,
                        _operator_reimburse_address,
                    );

                    // sign move_tx utxo
                    yield convert_tx_to_pubkey_spend(
                        &mut happy_reimburse_txhandler,
                        0,
                        None
                    )?;

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
                                &[0u8; 20], // TODO: real op unlock hash
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

                    let (assert_tx_addrs, root_hash, public_input_wots) = db.get_bitvm_setup(None, operator_idx as i32, time_tx_idx as i32, kickoff_idx as i32).await?.ok_or(BridgeError::BitvmSetupNotFound(operator_idx as i32, time_tx_idx as i32, kickoff_idx as i32))?;
                    let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
                        &kickoff_txhandler,
                        &assert_tx_addrs,
                        network,
                    );

                    let mut assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
                        &kickoff_txhandler,
                        &assert_begin_txhandler,
                        &assert_tx_addrs,
                        &root_hash,
                        nofn_xonly_pk,
                        public_input_wots,
                        network,
                    );
                    yield convert_tx_to_pubkey_spend(
                        &mut assert_end_txhandler,
                        PARALLEL_ASSERT_TX_CHAIN_SIZE,
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
                        _operator_reimburse_address,
                    );

                    yield convert_tx_to_pubkey_spend(&mut reimburse_txhandler, 0, None)?;
                }

                input_txid = reimburse_generator_txhandler.txid;
                input_amount = reimburse_generator_txhandler.tx.output[0].value;
            }
        }
    }
}
