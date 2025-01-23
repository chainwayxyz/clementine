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

// WIP: For now, this is equal to the number of sighashes we yield in create_nofn_sighash_stream.
// This will change as we implement the system design.
pub fn calculate_num_required_sigs(config: &BridgeConfig) -> usize {
    config.num_operators
        * config.num_time_txs
        * config.num_kickoffs_per_timetx
        * (10 + 2 * config.num_watchtowers)
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
            // Get all the watchtower Winternitz pubkeys for this operator. We have all of them here (for all the kickoff_utxos).
            let watchtower_all_challenge_winternitz_pks = (0..config.num_watchtowers)
                .map(|i| db.get_watchtower_winternitz_public_keys(None, i as u32, operator_idx as u32))
                .collect::<Vec<_>>();
            let watchtower_all_challenge_winternitz_pks =
                futures::future::try_join_all(watchtower_all_challenge_winternitz_pks).await?;

            let mut input_txid = *collateral_funding_txid;
            let mut input_amount = collateral_funding_amount;

            // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
            for time_tx_idx in 0..config.num_time_txs {
                // Create the sequential_collateral_tx handler.
                let sequential_collateral_txhandler = builder::transaction::create_sequential_collateral_txhandler(
                    *operator_xonly_pk,
                    input_txid,
                    input_amount,
                    timeout_block_count,
                    max_withdrawal_time_block_count,
                    config.num_kickoffs_per_timetx,
                    network,
                );

                // Create the reimburse_generator_tx handler.
                let reimburse_generator_txhandler = builder::transaction::create_reimburse_generator_txhandler(
                    &sequential_collateral_txhandler,
                    *operator_xonly_pk,
                    config.num_kickoffs_per_timetx,
                    max_withdrawal_time_block_count,
                    network,
                );

                // For each kickoff_utxo, it connnects to a kickoff_tx that results in
                // either start_happy_reimburse_tx
                // or challenge_tx, which forces the operator to initiate BitVM sequence
                // (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
                // If the operator is honest, the sequence will end with the operator being able to send the reimburse_tx.
                // Otherwise, by using the disprove_tx, the operator's sequential_collateral_tx burn connector will be burned.
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

                    // Yields the sighash for the challenge_tx.input[0], which spends kickoff_tx.input[1] using SinglePlusAnyoneCanPay.
                    yield challenge_tx.calculate_pubkey_spend_sighash(
                        0,
                        Some(bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
                    )?;

                    // Creates the start_happy_reimburse_tx handler.
                    let mut start_happy_reimburse_txhandler = builder::transaction::create_start_happy_reimburse_txhandler(
                        &kickoff_txhandler,
                        *operator_xonly_pk,
                        network
                    );

                    // Yields the sighash for the start_happy_reimburse_tx.input[1], which spends kickoff_tx.output[3].
                    yield start_happy_reimburse_txhandler.calculate_pubkey_spend_sighash(
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

                    // Yields the sighash for the happy_reimburse_tx.input[0], which spends move_to_vault_tx.output[0].
                    yield happy_reimburse_txhandler.calculate_pubkey_spend_sighash(
                        0,
                        None
                    )?;

                    // Collect the challenge Winternitz pubkeys for this specific kickoff_utxo.
                    let watchtower_challenge_winternitz_pks = (0..config.num_watchtowers)
                        .map(|i| watchtower_all_challenge_winternitz_pks[i][time_tx_idx * config.num_kickoffs_per_timetx + kickoff_idx].clone())
                        .collect::<Vec<_>>();

                    // Creates the watchtower_challenge_kickoff_tx handler.
                    let mut watchtower_challenge_kickoff_txhandler =
                        builder::transaction::create_watchtower_challenge_kickoff_txhandler(
                            &kickoff_txhandler,
                            config.num_watchtowers as u32,
                            &watchtower_pks,
                            &watchtower_challenge_winternitz_pks,
                            network,
                        );

                    // Yields the sighash for the watchtower_challenge_kickoff_tx.input[0], which spends kickoff_tx.input[0].
                    yield watchtower_challenge_kickoff_txhandler.calculate_pubkey_spend_sighash(
                        0,
                        None,
                    )?;

                    // Creates the kickoff_timeout_tx handler.
                    let mut kickoff_timeout_txhandler = builder::transaction::create_kickoff_timeout_txhandler(
                        &kickoff_txhandler,
                        &sequential_collateral_txhandler,
                        network,
                    );

                    // Yields the sighash for the kickoff_timeout_tx.input[0], which spends kickoff_tx.output[3].
                    yield kickoff_timeout_txhandler.calculate_script_spend_sighash(
                        0,
                        0,
                        None,
                    )?;

                    // Each watchtower will sign their Groth16 proof of the header chain circuit. Then, the operator will either
                    // - acknowledge the challenge by sending the operator_challenge_ACK_tx, which will prevent the burning of the kickoff_tx.output[2],
                    // - or do nothing, which will cause one to send the operator_challenge_NACK_tx, which will burn the kickoff_tx.output[2]
                    // using watchtower_challenge_tx.output[0].
                    for i in 0..config.num_watchtowers {
                        // Creates the watchtower_challenge_tx handler.
                        let watchtower_challenge_txhandler =
                            builder::transaction::create_watchtower_challenge_txhandler(
                                &watchtower_challenge_kickoff_txhandler,
                                i,
                                &[0u8; 20], // TODO: @ozankaymak real op unlock hash PUT THE HASHES OF THE PREIMAGES HERE
                                nofn_xonly_pk,
                                *operator_xonly_pk,
                                network,
                            );

                        // Creates the operator_challenge_NACK_tx handler.
                        let mut operator_challenge_nack_txhandler =
                            builder::transaction::create_operator_challenge_nack_txhandler(
                                &watchtower_challenge_txhandler,
                                &kickoff_txhandler
                            );

                        // Yields the sighash for the operator_challenge_NACK_tx.input[0], which spends watchtower_challenge_tx.output[0].
                        yield operator_challenge_nack_txhandler.calculate_script_spend_sighash(
                            0,
                            1,
                            None,
                        )?;

                        // Yields the sighash for the operator_challenge_NACK_tx.input[1], which spends kickoff_tx.output[2].
                        yield operator_challenge_nack_txhandler.calculate_pubkey_spend_sighash(
                            1,
                            None,
                        )?;
                    }

                    let (assert_tx_addrs, root_hash, public_input_wots) = db.get_bitvm_setup(None, operator_idx as i32, time_tx_idx as i32, kickoff_idx as i32).await?.ok_or(BridgeError::BitvmSetupNotFound(operator_idx as i32, time_tx_idx as i32, kickoff_idx as i32))?;

                    // Creates the assert_begin_tx handler.
                    let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
                        &kickoff_txhandler,
                        &assert_tx_addrs,
                        network,
                    );

                    // Creates the assert_end_tx handler.
                    let mut assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
                        &kickoff_txhandler,
                        &assert_begin_txhandler,
                        &assert_tx_addrs,
                        &root_hash,
                        nofn_xonly_pk,
                        &public_input_wots,
                        network,
                    );

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
                    );

                    // Yields the sighash for the disprove_timeout_tx.input[0], which spends assert_end_tx.output[0].
                    yield disprove_timeout_txhandler.calculate_pubkey_spend_sighash(
                        0,
                        None,
                    )?;

                    // Yields the disprove_timeout_tx.input[1], which spends assert_end_tx.output[1].
                    yield disprove_timeout_txhandler.calculate_script_spend_sighash(
                        1,
                        0,
                        None,
                    )?;

                    // Creates the already_disproved_tx handler.
                    let mut already_disproved_txhandler = builder::transaction::create_already_disproved_txhandler(
                        &assert_end_txhandler,
                        &sequential_collateral_txhandler,
                    );

                    // Yields the sighash for the already_disproved_tx.input[0], which spends assert_end_tx.output[1].
                    yield already_disproved_txhandler.calculate_script_spend_sighash(
                        0,
                        1,
                        None,
                    )?;

                    // Creates the reimburse_tx handler.
                    let mut reimburse_txhandler = builder::transaction::create_reimburse_txhandler(
                        &move_txhandler,
                        &disprove_timeout_txhandler,
                        &reimburse_generator_txhandler,
                        kickoff_idx,
                        operator_reimburse_address,
                    );

                    // Yields the sighash for the reimburse_tx.input[0], which spends move_to_vault_tx.output[0].
                    yield reimburse_txhandler.calculate_pubkey_spend_sighash(0, None)?;
                }

                input_txid = reimburse_generator_txhandler.txid;
                input_amount = reimburse_generator_txhandler.tx.output[0].value;
            }
        }
    }
}
