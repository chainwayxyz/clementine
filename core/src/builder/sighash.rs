//! # Sighash Builder
//!
//! Sighash builder provides useful functions for building related SigHashes.
//! Sighash is the message that is signed by the private key of the signer. It is used to signal
//! under which conditions the input is signed. For more, see:
//! https://developer.bitcoin.org/devguide/transactions.html?highlight=sighash#signature-hash-types

use crate::config::BridgeConfig;
use crate::constants::PARALLEL_ASSERT_TX_CHAIN_SIZE;
use crate::errors::BridgeError;
use crate::{builder, database::Database, EVMAddress};
use async_stream::try_stream;
use bitcoin::{address::NetworkUnchecked, Address, Amount, OutPoint};
use bitcoin::{TapSighash, Txid, XOnlyPublicKey};
use futures_core::stream::Stream;

/// Returns the number of required signatures for N-of-N signing session.
pub fn calculate_num_required_nofn_sigs(config: &BridgeConfig) -> usize {
    config.num_operators
        * config.num_sequential_collateral_txs
        * config.num_kickoffs_per_sequential_collateral_tx
        * (10 + 2 * config.num_watchtowers)
}

// WIP: For now, this is equal to the number of sighashes we yield in create_operator_sighash_stream.
// This will change as we implement the system design.
pub fn calculate_num_required_operator_sigs(config: &BridgeConfig) -> usize {
    config.num_sequential_collateral_txs * config.num_kickoffs_per_sequential_collateral_tx * 3
}

/// Refer to bridge design diagram to see which NofN signatures are needed (the ones marked with blue arrows).
/// These sighashes are needed in order to create the message to be signed later for MuSig2 of NofN.
/// WIP: Update if the design changes.
/// For a given deposit tx, for each operator and sequential_collateral tx, generates the sighash stream for:
/// - challenge_tx,
/// - start_happy_reimburse_tx,
/// - happy_reimburse_tx,
/// - watchtower_challenge_kickoff_tx,
/// - kickoff_timeout_tx,
/// - for each watchtower, operator_challenge_NACK_tx (for 2 inputs),
/// - assert_end_tx,
/// - disprove_timeout_tx (for 2 inputs),
/// - already_disproved_tx,
/// - reimburse_tx.
pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    _evm_address: EVMAddress,
    _recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    _user_takes_after: u16,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: u16,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    use bitcoin::TapSighashType::All as SighashAll;
    try_stream! {
        // Create move_tx handler. This is unique for each deposit tx.
        let move_txhandler = builder::transaction::create_move_to_vault_txhandler(
            deposit_outpoint,
            _evm_address,
            &_recovery_taproot_address,
            nofn_xonly_pk,
            _user_takes_after,
            bridge_amount_sats,
            network,
        )?;
        // Get operator details (for each operator, (X-Only Public Key, Address, Collateral Funding Txid))
        let operators: Vec<(XOnlyPublicKey, bitcoin::Address, Txid)> =
            db.get_operators(None).await?;
        if operators.len() < config.num_operators {
            Err(BridgeError::NotEnoughOperators)?;
        }

        for (operator_idx, (operator_xonly_pk, operator_reimburse_address, collateral_funding_txid)) in
            operators.iter().enumerate()
        {
            // Get all the watchtower challenge addresses for this operator. We have all of them here (for all the kickoff_utxos).
            // TODO: Make this more efficient
            let watchtower_all_challenge_addresses = (0..config.num_watchtowers)
                .map(|i| db.get_watchtower_challenge_addresses(None, i as u32, operator_idx as u32))
                .collect::<Vec<_>>();
            let watchtower_all_challenge_addresses = futures::future::try_join_all(watchtower_all_challenge_addresses).await?;

            let mut input_txid = *collateral_funding_txid;
            let mut input_amount = collateral_funding_amount;

            // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
            for sequential_collateral_tx_idx in 0..config.num_sequential_collateral_txs {
                // Create the sequential_collateral_tx handler.
                let sequential_collateral_txhandler = builder::transaction::create_sequential_collateral_txhandler(
                    *operator_xonly_pk,
                    input_txid,
                    input_amount,
                    timeout_block_count,
                    max_withdrawal_time_block_count,
                    config.num_kickoffs_per_sequential_collateral_tx,
                    network,
                );

                // Create the reimburse_generator_tx handler.
                let reimburse_generator_txhandler = builder::transaction::create_reimburse_generator_txhandler(
                    &sequential_collateral_txhandler,
                    *operator_xonly_pk,
                    config.num_kickoffs_per_sequential_collateral_tx,
                    max_withdrawal_time_block_count,
                    network,
                )?;

                // For each kickoff_utxo, it connnects to a kickoff_tx that results in
                // either start_happy_reimburse_tx
                // or challenge_tx, which forces the operator to initiate BitVM sequence
                // (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
                // If the operator is honest, the sequence will end with the operator being able to send the reimburse_tx.
                // Otherwise, by using the disprove_tx, the operator's sequential_collateral_tx burn connector will be burned.
                for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    let kickoff_txhandler = builder::transaction::create_kickoff_txhandler(
                        &sequential_collateral_txhandler,
                        kickoff_idx,
                        nofn_xonly_pk,
                        *operator_xonly_pk,
                        *move_txhandler.get_txid(),
                        operator_idx,
                        network,
                    )?;

                    // Creates the challenge_tx handler.
                    let challenge_tx = builder::transaction::create_challenge_txhandler(
                        &kickoff_txhandler,
                        operator_reimburse_address,
                    )?;

                    // Yields the sighash for the challenge_tx.input[0], which spends kickoff_tx.input[1] using SinglePlusAnyoneCanPay.
                    yield challenge_tx.calculate_pubkey_spend_sighash(
                        0,
                        Some(bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
                    )?;

                    // Creates the start_happy_reimburse_tx handler.
                    let start_happy_reimburse_txhandler = builder::transaction::create_start_happy_reimburse_txhandler(
                        &kickoff_txhandler,
                        *operator_xonly_pk,
                        network
                    )?;

                    // Yields the sighash for the start_happy_reimburse_tx.input[1], which spends kickoff_tx.output[3].
                    yield start_happy_reimburse_txhandler.calculate_pubkey_spend_sighash(
                        1,
                        None
                    )?;

                    // Creates the happy_reimburse_tx handler.
                    let happy_reimburse_txhandler = builder::transaction::create_happy_reimburse_txhandler(
                        &move_txhandler,
                        &start_happy_reimburse_txhandler,
                        &reimburse_generator_txhandler,
                        kickoff_idx,
                        operator_reimburse_address,
                    )?;

                    // Yields the sighash for the happy_reimburse_tx.input[0], which spends move_to_vault_tx.output[0].
                    yield happy_reimburse_txhandler.calculate_pubkey_spend_sighash(
                        0,
                        None
                    )?;

                    // Collect the challenge Winternitz pubkeys for this specific kickoff_utxo.
                    let watchtower_challenge_addresses = (0..config.num_watchtowers)
                        .map(|i| watchtower_all_challenge_addresses[i][sequential_collateral_tx_idx * config.num_kickoffs_per_sequential_collateral_tx + kickoff_idx].clone())
                        .collect::<Vec<_>>();

                    let  watchtower_challenge_kickoff_txhandler =
                        builder::transaction::create_watchtower_challenge_kickoff_txhandler_simplified(
                            &kickoff_txhandler,
                            config.num_watchtowers as u32,
                            &watchtower_challenge_addresses,
                        )?;

                    // Yields the sighash for the watchtower_challenge_kickoff_tx.input[0], which spends kickoff_tx.input[0].
                    yield watchtower_challenge_kickoff_txhandler.calculate_pubkey_spend_sighash(
                        0,
                        None,
                    )?;

                    // Creates the kickoff_timeout_tx handler.
                    let mut kickoff_timeout_txhandler = builder::transaction::create_kickoff_timeout_txhandler(
                        &kickoff_txhandler,
                        &sequential_collateral_txhandler,
                    )?;

                    // Yields the sighash for the kickoff_timeout_tx.input[0], which spends kickoff_tx.output[3].
                    yield kickoff_timeout_txhandler.calculate_script_spend_sighash_indexed(
                        0,
                        0,
                        SighashAll
                    )?;
                    let public_hashes = db.get_operators_challenge_ack_hashes(None, operator_idx as i32, sequential_collateral_tx_idx as i32, kickoff_idx as i32).await?.ok_or(BridgeError::WatchtowerPublicHashesNotFound(operator_idx as i32, sequential_collateral_tx_idx as i32, kickoff_idx as i32))?;
                    // Each watchtower will sign their Groth16 proof of the header chain circuit. Then, the operator will either
                    // - acknowledge the challenge by sending the operator_challenge_ACK_tx, which will prevent the burning of the kickoff_tx.output[2],
                    // - or do nothing, which will cause one to send the operator_challenge_NACK_tx, which will burn the kickoff_tx.output[2]
                    // using watchtower_challenge_tx.output[0].
                    for (watchtower_idx, public_hash) in public_hashes.iter().enumerate() {
                        // Creates the watchtower_challenge_tx handler.
                        let watchtower_challenge_txhandler =
                            builder::transaction::create_watchtower_challenge_txhandler(
                                &watchtower_challenge_kickoff_txhandler,
                                watchtower_idx,
                                public_hash,
                                nofn_xonly_pk,
                                *operator_xonly_pk,
                                network,
                            )?;

                        // Creates the operator_challenge_NACK_tx handler.
                        let mut operator_challenge_nack_txhandler =
                            builder::transaction::create_operator_challenge_nack_txhandler(
                                &watchtower_challenge_txhandler,
                                &kickoff_txhandler
                            )?;

                        // Yields the sighash for the operator_challenge_NACK_tx.input[0], which spends watchtower_challenge_tx.output[0].
                        yield operator_challenge_nack_txhandler.calculate_script_spend_sighash_indexed(
                            0,
                            1,
                            SighashAll,
                        )?;

                        // Yields the sighash for the operator_challenge_NACK_tx.input[1], which spends kickoff_tx.output[2].
                        yield operator_challenge_nack_txhandler.calculate_pubkey_spend_sighash(
                            1,
                            None,
                        )?;
                    }

                    let (assert_tx_addrs, root_hash, public_input_wots) = db.get_bitvm_setup(None, operator_idx as i32, sequential_collateral_tx_idx as i32, kickoff_idx as i32).await?.ok_or(BridgeError::BitvmSetupNotFound(operator_idx as i32, sequential_collateral_tx_idx as i32, kickoff_idx as i32))?;

                    // Creates the assert_begin_tx handler.
                    let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
                        &kickoff_txhandler,
                        &assert_tx_addrs,
                        network,
                    )?;

                    // Creates the assert_end_tx handler.
                    let assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
                        &kickoff_txhandler,
                        &assert_begin_txhandler,
                        &assert_tx_addrs,
                        &root_hash,
                        nofn_xonly_pk,
                        &public_input_wots,
                        network,
                    )?;

                    // Yields the sighash for the assert_end_tx, which spends kickoff_tx.output[3].
                    yield assert_end_txhandler.calculate_pubkey_spend_sighash(
                        PARALLEL_ASSERT_TX_CHAIN_SIZE,
                        None,
                    )?;

                    // Creates the disprove_timeout_tx handler.
                    let mut disprove_timeout_txhandler = builder::transaction::create_disprove_timeout_txhandler(
                        &assert_end_txhandler,
                        *operator_xonly_pk,
                        network,
                    )?;

                    // Yields the sighash for the disprove_timeout_tx.input[0], which spends assert_end_tx.output[0].
                    yield disprove_timeout_txhandler.calculate_pubkey_spend_sighash(
                        0,
                        None,
                    )?;

                    // Yields the disprove_timeout_tx.input[1], which spends assert_end_tx.output[1].
                    yield disprove_timeout_txhandler.calculate_script_spend_sighash_indexed(
                        1,
                        0,
                        SighashAll,
                    )?;

                    // Creates the already_disproved_tx handler.
                    let mut already_disproved_txhandler = builder::transaction::create_already_disproved_txhandler(
                        &assert_end_txhandler,
                        &sequential_collateral_txhandler,
                    )?;

                    // Yields the sighash for the already_disproved_tx.input[0], which spends assert_end_tx.output[1].
                    yield already_disproved_txhandler.calculate_script_spend_sighash_indexed(
                        0,
                        1,
                        SighashAll,
                    )?;

                    // Creates the reimburse_tx handler.
                    let reimburse_txhandler = builder::transaction::create_reimburse_txhandler(
                        &move_txhandler,
                        &disprove_timeout_txhandler,
                        &reimburse_generator_txhandler,
                        kickoff_idx,
                        operator_reimburse_address,
                    )?;

                    // Yields the sighash for the reimburse_tx.input[0], which spends move_to_vault_tx.output[0].
                    yield reimburse_txhandler.calculate_pubkey_spend_sighash(0, None)?;
                }

                input_txid = *reimburse_generator_txhandler.get_txid();
                input_amount = reimburse_generator_txhandler.get_spendable_output(0).ok_or(BridgeError::TxInputNotFound)?.get_prevout().value;
            }
        }
    }
}

/// Refer to bridge design diagram to see which Operator signatures are needed (the ones marked with red arrows).
/// These operator sighashes are needed so that each operator can share the signatures with each verifier, so that
/// verifiers have the ability to burn the burn connector of operators.
/// WIP: Update if the design changes.
/// This function generates Kickoff Timeout TX, Already Disproved TX,
/// and Disprove TX for each sequential_collateral_tx and kickoff_utxo. It yields the sighashes for these tx's for the input that has operators burn connector.
/// Possible future optimization: Each verifier already generates some of these TX's in create_operator_sighash_stream()
/// It is possible to for verifiers somehow return the required sighashes for operator signatures there too. But operators only needs to use sighashes included in this function.
pub fn create_operator_sighash_stream(
    db: Database,
    operator_idx: usize,
    collateral_funding_txid: Txid,
    operator_xonly_pk: XOnlyPublicKey,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    _evm_address: EVMAddress,
    _recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    _user_takes_after: u16,
    collateral_funding_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: u16,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> impl Stream<Item = Result<TapSighash, BridgeError>> {
    try_stream! {
        // Create move_tx handler. This is unique for each deposit tx.
        let move_txhandler = builder::transaction::create_move_to_vault_txhandler(
            deposit_outpoint,
            _evm_address,
            &_recovery_taproot_address,
            nofn_xonly_pk,
            _user_takes_after,
            bridge_amount_sats,
            network,
        )?;

        let mut input_txid = collateral_funding_txid;
        let mut input_amount = collateral_funding_amount;

        // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
        for time_tx_idx in 0..config.num_sequential_collateral_txs {
            // Create the sequential_collateral_tx handler.
            let sequential_collateral_txhandler = builder::transaction::create_sequential_collateral_txhandler(
                operator_xonly_pk,
                input_txid,
                input_amount,
                timeout_block_count,
                max_withdrawal_time_block_count,
                config.num_kickoffs_per_sequential_collateral_tx,
                network,
            );

            // Create the reimburse_generator_tx handler.
            let reimburse_generator_txhandler = builder::transaction::create_reimburse_generator_txhandler(
                &sequential_collateral_txhandler,
                operator_xonly_pk,
                config.num_kickoffs_per_sequential_collateral_tx,
                max_withdrawal_time_block_count,
                network,
            )?;

            // For each kickoff_utxo, it connnects to a kickoff_tx that results in
            // either start_happy_reimburse_tx
            // or challenge_tx, which forces the operator to initiate BitVM sequence
            // (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
            // If the operator is honest, the sequence will end with the operator being able to send the reimburse_tx.
            // Otherwise, by using the disprove_tx, the operator's sequential_collateral_tx burn connector will be burned.
            for kickoff_idx in 0..config.num_kickoffs_per_sequential_collateral_tx {
                let kickoff_txhandler = builder::transaction::create_kickoff_txhandler(
                    &sequential_collateral_txhandler,
                    kickoff_idx,
                    nofn_xonly_pk,
                    operator_xonly_pk,
                    *move_txhandler.get_txid(),
                    operator_idx,
                    network,
                )?;

                // Creates the kickoff_timeout_tx handler.
                let kickoff_timeout_txhandler = builder::transaction::create_kickoff_timeout_txhandler(
                    &kickoff_txhandler,
                    &sequential_collateral_txhandler,
                )?;

                // Yields the sighash for the kickoff_timeout_tx.input[0], which spends kickoff_tx.output[3].
                yield kickoff_timeout_txhandler.calculate_pubkey_spend_sighash(
                    1,
                    None,
                )?;

                let (assert_tx_addrs, root_hash, public_input_wots) = db.get_bitvm_setup(None, operator_idx as i32, time_tx_idx as i32, kickoff_idx as i32).await?.ok_or(BridgeError::BitvmSetupNotFound(operator_idx as i32, time_tx_idx as i32, kickoff_idx as i32))?;

                // Creates the assert_begin_tx handler.
                let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
                    &kickoff_txhandler,
                    &assert_tx_addrs,
                    network,
                )?;

                // Creates the assert_end_tx handler.
                let assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
                    &kickoff_txhandler,
                    &assert_begin_txhandler,
                    &assert_tx_addrs,
                    &root_hash,
                    nofn_xonly_pk,
                    &public_input_wots,
                    network,
                )?;

                // Creates the already_disproved_tx handler.
                let already_disproved_txhandler = builder::transaction::create_already_disproved_txhandler(
                    &assert_end_txhandler,
                    &sequential_collateral_txhandler,
                )?;

                // Yields the sighash for the already_disproved_tx.input[0], which spends assert_end_tx.output[1].
                yield already_disproved_txhandler.calculate_pubkey_spend_sighash(
                    1,
                    None,
                )?;

                let disprove_txhandler = builder::transaction::create_disprove_txhandler(
                    &assert_end_txhandler,
                    &sequential_collateral_txhandler,
                )?;

                // Yields the sighash for the disprove_tx.input[1], which spends sequential_collateral_tx.output[0].
                yield disprove_txhandler.calculate_pubkey_spend_sighash(
                    1,
                    None,
                )?;
            }

            input_txid = *reimburse_generator_txhandler.get_txid();
            input_amount = reimburse_generator_txhandler.get_spendable_output(0).ok_or(BridgeError::TxInputNotFound)?.get_prevout().value;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::sighash::create_nofn_sighash_stream;
    use crate::extended_rpc::ExtendedRpc;
    use crate::operator::Operator;
    use crate::utils::BITVM_CACHE;
    use crate::watchtower::Watchtower;
    use crate::{builder, create_test_config_with_thread_name, utils};
    use crate::{
        config::BridgeConfig, database::Database, initialize_database, utils::initialize_logger,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TapSighash, Txid, XOnlyPublicKey};
    use futures::StreamExt;
    use std::pin::pin;
    use std::{env, thread};

    #[tokio::test]
    async fn calculate_num_required_nofn_sigs() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        let operator = Operator::new(config.clone(), rpc).await.unwrap();
        let watchtower = Watchtower::new(config.clone()).await.unwrap();

        // Dummy inputs for nofn_stream.
        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };
        let evm_address = crate::EVMAddress([0x45; 20]);
        let recovery_taproot_address =
            builder::address::create_taproot_address(&[], None, bitcoin::Network::Regtest).0;
        let nofn_xonly_pk = XOnlyPublicKey::from_slice(&[0x45; 32]).unwrap();
        let collateral_funding_amount = Amount::from_sat(0x1F);
        let timeout_block_count = 0x1F;
        let max_withdrawal_time_block_count = 100 - 0x1F;
        let bridge_amount_sats = Amount::from_sat(100 - 0x45);

        // Initialize database.
        let operator_xonly_pk = XOnlyPublicKey::from_slice(&[0x45; 32]).unwrap();
        let watchtower_xonly_pk = XOnlyPublicKey::from_slice(&[0x1F; 32]).unwrap();
        for i in 0..config.num_operators {
            db.set_operator(
                None,
                i.try_into().unwrap(),
                operator_xonly_pk,
                recovery_taproot_address.to_string(),
                Txid::all_zeros(),
            )
            .await
            .unwrap();
        }
        for i in 0..config.num_watchtowers {
            db.set_watchtower_xonly_pk(None, i.try_into().unwrap(), &watchtower_xonly_pk)
                .await
                .unwrap();
        }
        for i in 0..config.num_operators {
            db.set_operator_winternitz_public_keys(
                None,
                i.try_into().unwrap(),
                operator.get_winternitz_public_keys().unwrap(),
            )
            .await
            .unwrap();
        }
        for i in 0..config.num_operators {
            for j in 0..config.num_watchtowers {
                db.set_watchtower_challenge_addresses(
                    None,
                    j.try_into().unwrap(),
                    i.try_into().unwrap(),
                    watchtower
                        .get_watchtower_challenge_addresses()
                        .await
                        .unwrap(),
                )
                .await
                .unwrap();
            }
        }
        let assert_len = BITVM_CACHE.intermediate_variables.len();
        for o in 0..config.num_operators {
            for t in 0..config.num_sequential_collateral_txs {
                for k in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    db.set_bitvm_setup(
                        None,
                        o.try_into().unwrap(),
                        t.try_into().unwrap(),
                        k.try_into().unwrap(),
                        vec![ScriptBuf::default(); assert_len],
                        &[0x45; 32],
                        vec![],
                    )
                    .await
                    .unwrap();
                }
            }
        }
        for o in 0..config.num_operators {
            for t in 0..config.num_sequential_collateral_txs {
                for k in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    db.set_operator_challenge_ack_hashes(
                        None,
                        o.try_into().unwrap(),
                        t.try_into().unwrap(),
                        k.try_into().unwrap(),
                        vec![[0x45; 20]; config.num_watchtowers],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let mut nofn_stream = pin!(create_nofn_sighash_stream(
            db,
            config.clone(),
            deposit_outpoint,
            evm_address,
            recovery_taproot_address.as_unchecked().clone(),
            nofn_xonly_pk,
            config.user_takes_after,
            collateral_funding_amount,
            timeout_block_count,
            max_withdrawal_time_block_count,
            bridge_amount_sats,
            bitcoin::Network::Regtest,
        ));

        let mut challenge_tx_sighashes = Vec::<TapSighash>::new();
        let mut start_happy_reimburse_sighashes = Vec::<TapSighash>::new();
        let mut happy_reimburse_sighashes = Vec::<TapSighash>::new();
        let mut watchtower_challenge_kickoff_sighashes = Vec::<TapSighash>::new();
        let mut kickoff_timeout_sighashes = Vec::<TapSighash>::new();
        let mut operator_challenge_nack_sighashes = Vec::<TapSighash>::new();
        let mut assert_end_sighashes = Vec::<TapSighash>::new();
        let mut disprove_timeout_sighashes = Vec::<TapSighash>::new();
        let mut already_disproved_sighashes = Vec::<TapSighash>::new();
        let mut reimburse_sighashes = Vec::<TapSighash>::new();

        for _ in 0..config.num_operators {
            for _ in 0..config.num_sequential_collateral_txs {
                for _ in 0..config.num_kickoffs_per_sequential_collateral_tx {
                    challenge_tx_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                    start_happy_reimburse_sighashes
                        .push(nofn_stream.next().await.unwrap().unwrap());
                    happy_reimburse_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                    watchtower_challenge_kickoff_sighashes
                        .push(nofn_stream.next().await.unwrap().unwrap());
                    kickoff_timeout_sighashes.push(nofn_stream.next().await.unwrap().unwrap());

                    for _ in 0..config.num_watchtowers {
                        // Script spend.
                        operator_challenge_nack_sighashes
                            .push(nofn_stream.next().await.unwrap().unwrap());
                        // Pubkey spend.
                        operator_challenge_nack_sighashes
                            .push(nofn_stream.next().await.unwrap().unwrap());
                    }

                    assert_end_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                    // Pubkey spend.
                    disprove_timeout_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                    // Script spend.
                    disprove_timeout_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                    already_disproved_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                    reimburse_sighashes.push(nofn_stream.next().await.unwrap().unwrap());
                }
            }
        }
        assert!(nofn_stream.next().await.is_none());

        let sum = challenge_tx_sighashes.len()
            + start_happy_reimburse_sighashes.len()
            + happy_reimburse_sighashes.len()
            + watchtower_challenge_kickoff_sighashes.len()
            + kickoff_timeout_sighashes.len()
            + operator_challenge_nack_sighashes.len()
            + assert_end_sighashes.len()
            + disprove_timeout_sighashes.len()
            + already_disproved_sighashes.len()
            + reimburse_sighashes.len();
        assert_eq!(sum, super::calculate_num_required_nofn_sigs(&config));
    }
}
