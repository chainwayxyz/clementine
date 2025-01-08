use crate::builder::transaction::TxHandler;
use crate::config::BridgeConfig;
use crate::constants::NUM_INTERMEDIATE_STEPS;
use crate::errors::BridgeError;
use crate::{builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint, TapLeafHash, TapSighashType};
use bitcoin::{TapSighash, Txid};
use futures_core::stream::Stream;

pub fn calculate_num_required_sigs(
    num_operators: usize,
    num_time_txs: usize,
    num_watchtowers: usize,
) -> usize {
    num_operators * num_time_txs * (1 + 3 * num_watchtowers + 1)
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
            .scripts
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

/// First iterate over operators
/// For each operator, iterate over time txs
/// For each time tx, create kickoff txid
/// using kickoff txid, create watchtower challenge page
/// yield watchtower challenge page sighash
/// yield watchtower challenge tx sighash per watchtower
/// yield sighash_single|anyonecanpay sighash for challenge tx
/// TBC
pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    _evm_address: EVMAddress,
    _recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    _user_takes_after: u64,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    try_stream! {
        let move_txid = builder::transaction::create_move_tx(
            deposit_outpoint,
            nofn_xonly_pk,
            bridge_amount_sats,
            network,
        )
        .compute_txid();

        let operators: Vec<(secp256k1::XOnlyPublicKey, bitcoin::Address, Txid)> =
            db.get_operators(None).await?;
        if operators.len() < config.num_operators {
            panic!("Not enough operators");
        }

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
                let time_txid = builder::transaction::create_time_tx(
                    *operator_xonly_pk,
                    input_txid,
                    input_amount,
                    timeout_block_count,
                    max_withdrawal_time_block_count,
                    network,
                )
                .compute_txid();

                let kickoff_txid = builder::transaction::create_kickoff_tx(
                    time_txid,
                    nofn_xonly_pk,
                    *operator_xonly_pk,
                    move_txid,
                    operator_idx,
                    network,
                )
                .compute_txid();

                let mut challenge_tx = builder::transaction::create_challenge_txhandler(
                    kickoff_txid,
                    nofn_xonly_pk,
                    *operator_xonly_pk,
                    _operator_reimburse_address,
                    network
                );

                yield convert_tx_to_pubkey_spend(
                    &mut challenge_tx,
                    0,
                    Some(bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
                )?;

                let mut happy_reimburse_tx = builder::transaction::create_happy_reimburse_txhandler(
                    move_txid,
                    kickoff_txid,
                    nofn_xonly_pk,
                    *operator_xonly_pk,
                    _operator_reimburse_address,
                    bridge_amount_sats,
                    network,
                );

                // move utxo
                yield convert_tx_to_pubkey_spend(
                    &mut happy_reimburse_tx,
                    0,
                    None
                )?;
                // nofn_or_nofn3week utxo
                yield convert_tx_to_pubkey_spend(
                    &mut happy_reimburse_tx,
                    2,
                    None
                )?;


                let watchtower_wots = (0..config.num_watchtowers)
                    .map(|i| watchtower_challenge_wotss[i][time_tx_idx].clone())
                    .collect::<Vec<_>>();

                let mut watchtower_challenge_page_tx_handler =
                    builder::transaction::create_watchtower_challenge_page_txhandler(
                        kickoff_txid,
                        nofn_xonly_pk,
                        config.num_watchtowers as u32,
                        watchtower_wots.clone(),
                        network,
                    );

                yield convert_tx_to_pubkey_spend(
                    &mut watchtower_challenge_page_tx_handler,
                    0,
                    None,
                )?;

                let wcp_txid = watchtower_challenge_page_tx_handler.tx.compute_txid();

                for (i, watchtower_wots) in watchtower_wots.iter().enumerate().take(config.num_watchtowers) {
                    let mut watchtower_challenge_txhandler =
                        builder::transaction::create_watchtower_challenge_txhandler(
                            wcp_txid,
                            i,
                            watchtower_wots.clone(),
                            &[0u8; 20],
                            nofn_xonly_pk,
                            *operator_xonly_pk,
                            network,
                        );
                    yield convert_tx_to_script_spend(
                        &mut watchtower_challenge_txhandler,
                        0,
                        0,
                        None,
                    )?;

                    let mut operator_challenge_nack_txhandler =
                        builder::transaction::create_operator_challenge_nack_txhandler(
                            watchtower_challenge_txhandler.tx.compute_txid(),
                            time_txid,
                            kickoff_txid,
                            input_amount,
                            &[0u8; 20],
                            nofn_xonly_pk,
                            *operator_xonly_pk,
                            network,
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
                let assert_begin_txid = builder::transaction::create_assert_begin_txhandler(
                    kickoff_txid,
                    nofn_xonly_pk,
                    *operator_xonly_pk,
                    intermediate_wots[time_tx_idx].clone(),
                    network,
                )
                .tx
                .compute_txid();

                let mut assert_end_tx = builder::transaction::create_assert_end_txhandler(
                    kickoff_txid,
                    assert_begin_txid,
                    nofn_xonly_pk,
                    *operator_xonly_pk,
                    network,
                );
                yield convert_tx_to_pubkey_spend(
                    &mut assert_end_tx,
                    NUM_INTERMEDIATE_STEPS,
                    None,
                )?;

                let mut disprove_tx = builder::transaction::create_disprove_txhandler(
                    assert_end_tx.tx.compute_txid(),
                    time_txid,
                    nofn_xonly_pk,
                    network,
                );

                // sign for all disprove scripts
                for i in 0..NUM_INTERMEDIATE_STEPS {
                    yield convert_tx_to_script_spend(
                        &mut disprove_tx,
                        0,
                        i,
                        Some(bitcoin::sighash::TapSighashType::None),
                    )?;
                }

                let time2_tx = builder::transaction::create_time2_tx(
                    *operator_xonly_pk,
                    time_txid,
                    input_amount,
                    network,
                );

                input_txid = time2_tx.compute_txid();
                input_amount = time2_tx.output[0].value;
            }
        }
    }
}

pub fn create_timout_tx_sighash_stream(
    operator_xonly_pk: secp256k1::XOnlyPublicKey,
    collateral_funding_txid: bitcoin::Txid,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    num_time_txs: usize,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    let mut input_txid = collateral_funding_txid;
    let mut input_amount = collateral_funding_amount;

    try_stream! {
        for _ in 0..num_time_txs {
            let time_tx = builder::transaction::create_time_tx(
                operator_xonly_pk,
                input_txid,
                input_amount,
                timeout_block_count,
                max_withdrawal_time_block_count,
                network,
            );

            let mut timeout_tx_handler = builder::transaction::create_timeout_tx_handler(
                operator_xonly_pk,
                time_tx.compute_txid(),
                timeout_block_count,
                network,
            );

            yield convert_tx_to_script_spend(&mut timeout_tx_handler, 0, 0, None)?;

            let time2_tx = builder::transaction::create_time2_tx(
                operator_xonly_pk,
                time_tx.compute_txid(),
                input_amount,
                network,
            );

            input_txid = time2_tx.compute_txid();
            input_amount = time2_tx.output[0].value;
        }
    }
}
