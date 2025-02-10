use crate::actor::{Actor, WinternitzDerivationPath};
use crate::builder::script::WinternitzCommit;
use crate::builder::transaction::{TransactionType, TxHandler};
use crate::config::BridgeConfig;
use crate::constants::{WATCHTOWER_CHALLENGE_MESSAGE_LENGTH, WINTERNITZ_LOG_D};
use crate::database::Database;
use crate::errors::BridgeError;
use crate::{builder, utils, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn create_txhandlers(
    db: Database,
    config: BridgeConfig,
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    transaction_type: TransactionType,
    operator_idx: usize,
    sequential_collateral_tx_idx: usize,
    kickoff_idx: usize,
    prev_reimburse_generator: Option<&TxHandler>,
    move_to_vault: Option<&TxHandler>, // to not generate them if they were already generated
) -> Result<HashMap<TransactionType, TxHandler>, BridgeError> {
    let mut txhandlers = HashMap::new();
    // Create move_tx handler. This is unique for each deposit tx.
    let move_txhandler = match move_to_vault {
        // TODO: do not clone
        Some(move_to_vault) => move_to_vault.clone(),
        None => builder::transaction::create_move_to_vault_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            nofn_xonly_pk,
            config.user_takes_after,
            config.bridge_amount_sats,
            config.network,
        )?,
    };
    txhandlers.insert(move_txhandler.get_transaction_type(), move_txhandler);

    // Get operator details (for each operator, (X-Only Public Key, Address, Collateral Funding Txid))
    let (operator_xonly_pk, operator_reimburse_address, collateral_funding_txid) =
        db.get_operator(None, operator_idx as i32).await?;

    let (sequential_collateral_txhandler, reimburse_generator_txhandler) =
        match prev_reimburse_generator {
            Some(prev_reimburse_generator) => {
                let sequential_collateral_txhandler =
                    builder::transaction::create_sequential_collateral_txhandler(
                        operator_xonly_pk,
                        *prev_reimburse_generator.get_txid(),
                        prev_reimburse_generator
                            .get_spendable_output(0)?
                            .get_prevout()
                            .value,
                        config.timeout_block_count,
                        config.max_withdrawal_time_block_count,
                        config.num_kickoffs_per_sequential_collateral_tx,
                        config.network,
                    )?;

                // Create the reimburse_generator_tx handler.
                let reimburse_generator_txhandler =
                    builder::transaction::create_reimburse_generator_txhandler(
                        &sequential_collateral_txhandler,
                        operator_xonly_pk,
                        config.num_kickoffs_per_sequential_collateral_tx,
                        config.max_withdrawal_time_block_count,
                        config.network,
                    )?;
                (
                    sequential_collateral_txhandler,
                    reimburse_generator_txhandler,
                )
            }
            None => {
                // create nth sequential collateral tx and reimburse generator tx for the operator
                let (sequential_collateral_txhandler, reimburse_generator_txhandler) =
                    builder::transaction::create_seq_collat_reimburse_gen_nth_txhandler(
                        operator_xonly_pk,
                        collateral_funding_txid,
                        config.collateral_funding_amount,
                        config.timeout_block_count,
                        config.num_kickoffs_per_sequential_collateral_tx,
                        config.max_withdrawal_time_block_count,
                        config.network,
                        sequential_collateral_tx_idx,
                    )?;
                (
                    sequential_collateral_txhandler,
                    reimburse_generator_txhandler,
                )
            }
        };

    txhandlers.insert(
        sequential_collateral_txhandler.get_transaction_type(),
        sequential_collateral_txhandler,
    );
    txhandlers.insert(
        reimburse_generator_txhandler.get_transaction_type(),
        reimburse_generator_txhandler,
    );

    let kickoff_txhandler = builder::transaction::create_kickoff_txhandler(
        txhandlers
            .get(&TransactionType::SequentialCollateral)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        kickoff_idx,
        nofn_xonly_pk,
        operator_xonly_pk,
        *txhandlers
            .get(&TransactionType::MoveToVault)
            .ok_or(BridgeError::TxHandlerNotFound)?
            .get_txid(),
        operator_idx,
        config.network,
    )?;
    txhandlers.insert(kickoff_txhandler.get_transaction_type(), kickoff_txhandler);

    // Creates the kickoff_timeout_tx handler.
    let kickoff_timeout_txhandler = builder::transaction::create_kickoff_timeout_txhandler(
        txhandlers
            .get(&TransactionType::Kickoff)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        txhandlers
            .get(&TransactionType::SequentialCollateral)
            .ok_or(BridgeError::TxHandlerNotFound)?,
    )?;
    txhandlers.insert(
        kickoff_timeout_txhandler.get_transaction_type(),
        kickoff_timeout_txhandler,
    );

    // Creates the challenge_tx handler.
    let challenge_tx = builder::transaction::create_challenge_txhandler(
        txhandlers
            .get(&TransactionType::Kickoff)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        &operator_reimburse_address,
    )?;
    txhandlers.insert(challenge_tx.get_transaction_type(), challenge_tx);

    // Generate Happy reimburse txs conditionally
    if matches!(
        transaction_type,
        TransactionType::StartHappyReimburse
            | TransactionType::Reimburse
            | TransactionType::AllNeededForVerifierDeposit
    ) {
        // Creates the start_happy_reimburse_tx handler.
        let start_happy_reimburse_txhandler =
            builder::transaction::create_start_happy_reimburse_txhandler(
                txhandlers
                    .get(&TransactionType::Kickoff)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
                operator_xonly_pk,
                config.network,
            )?;
        txhandlers.insert(
            start_happy_reimburse_txhandler.get_transaction_type(),
            start_happy_reimburse_txhandler,
        );

        // Creates the happy_reimburse_tx handler.
        let happy_reimburse_txhandler = builder::transaction::create_happy_reimburse_txhandler(
            txhandlers
                .get(&TransactionType::MoveToVault)
                .ok_or(BridgeError::TxHandlerNotFound)?,
            txhandlers
                .get(&TransactionType::StartHappyReimburse)
                .ok_or(BridgeError::TxHandlerNotFound)?,
            txhandlers
                .get(&TransactionType::ReimburseGenerator)
                .ok_or(BridgeError::TxHandlerNotFound)?,
            kickoff_idx,
            &operator_reimburse_address,
        )?;
        txhandlers.insert(
            happy_reimburse_txhandler.get_transaction_type(),
            happy_reimburse_txhandler,
        );
        if !matches!(
            transaction_type,
            TransactionType::AllNeededForOperatorDeposit
                | TransactionType::AllNeededForVerifierDeposit
        ) {
            // We do not need other txhandlers, exit early
            return Ok(txhandlers);
        }
    }

    // Generate watchtower challenges (addresses from db) if all txs are needed
    if matches!(
        transaction_type,
        TransactionType::AllNeededForVerifierDeposit
            | TransactionType::WatchtowerChallengeKickoff
            | TransactionType::WatchtowerChallenge(_)
            | TransactionType::OperatorChallengeNACK(_)
            | TransactionType::OperatorChallengeACK(_)
    ) {
        let needed_watchtower_idx: i32 =
            if let TransactionType::WatchtowerChallenge(idx) = transaction_type {
                idx as i32
            } else {
                -1
            };

        // Get all the watchtower challenge addresses for this operator. We have all of them here (for all the kickoff_utxos).
        // Optimize: Make this only return for a specific kickoff, but its only 40mb (33bytes * 60000 (kickoff per op?) * 20 (watchtower count)
        let watchtower_all_challenge_addresses = (0..config.num_watchtowers)
            .map(|i| db.get_watchtower_challenge_addresses(None, i as u32, operator_idx as u32))
            .collect::<Vec<_>>();
        let watchtower_all_challenge_addresses =
            futures::future::try_join_all(watchtower_all_challenge_addresses).await?;

        // Collect the challenge Winternitz pubkeys for this specific kickoff_utxo.
        let watchtower_challenge_addresses = (0..config.num_watchtowers)
            .map(|i| {
                watchtower_all_challenge_addresses[i][sequential_collateral_tx_idx
                    * config.num_kickoffs_per_sequential_collateral_tx
                    + kickoff_idx]
                    .clone()
            })
            .collect::<Vec<_>>();

        let watchtower_challenge_kickoff_txhandler =
            builder::transaction::create_watchtower_challenge_kickoff_txhandler_from_db(
                txhandlers
                    .get(&TransactionType::Kickoff)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
                config.num_watchtowers as u32,
                &watchtower_challenge_addresses,
            )?;
        txhandlers.insert(
            watchtower_challenge_kickoff_txhandler.get_transaction_type(),
            watchtower_challenge_kickoff_txhandler,
        );

        let public_hashes = db
            .get_operators_challenge_ack_hashes(
                None,
                operator_idx as i32,
                sequential_collateral_tx_idx as i32,
                kickoff_idx as i32,
            )
            .await?
            .ok_or(BridgeError::WatchtowerPublicHashesNotFound(
                operator_idx as i32,
                sequential_collateral_tx_idx as i32,
                kickoff_idx as i32,
            ))?;
        // Each watchtower will sign their Groth16 proof of the header chain circuit. Then, the operator will either
        // - acknowledge the challenge by sending the operator_challenge_ACK_tx, which will prevent the burning of the kickoff_tx.output[2],
        // - or do nothing, which will cause one to send the operator_challenge_NACK_tx, which will burn the kickoff_tx.output[2]
        // using watchtower_challenge_tx.output[0].
        for (watchtower_idx, public_hash) in public_hashes.iter().enumerate() {
            let watchtower_challenge_txhandler = if watchtower_idx as i32 != needed_watchtower_idx {
                // create it with db if we don't need actual winternitz script
                builder::transaction::create_watchtower_challenge_txhandler_from_db(
                    txhandlers
                        .get(&TransactionType::WatchtowerChallengeKickoff)
                        .ok_or(BridgeError::TxHandlerNotFound)?,
                    watchtower_idx,
                    public_hash,
                    nofn_xonly_pk,
                    operator_xonly_pk,
                    config.network,
                )?
            } else {
                // generate with actual scripts if we want to specifically create a watchtower challenge tx
                let path = WinternitzDerivationPath {
                    message_length: WATCHTOWER_CHALLENGE_MESSAGE_LENGTH,
                    log_d: WINTERNITZ_LOG_D,
                    tx_type: crate::actor::TxType::WatchtowerChallenge,
                    index: None,
                    operator_idx: Some(operator_idx as u32),
                    watchtower_idx: None,
                    sequential_collateral_tx_idx: Some(sequential_collateral_tx_idx as u32),
                    kickoff_idx: Some(kickoff_idx as u32),
                    intermediate_step_name: None,
                };
                let actor = Actor::new(
                    config.secret_key,
                    config.winternitz_secret_key,
                    config.network,
                );
                let public_key = actor.derive_winternitz_pk(path)?;
                let winternitz_params = winternitz::Parameters::new(
                    WATCHTOWER_CHALLENGE_MESSAGE_LENGTH,
                    WINTERNITZ_LOG_D,
                );

                builder::transaction::create_watchtower_challenge_txhandler_from_script(
                    txhandlers
                        .get(&TransactionType::WatchtowerChallengeKickoff)
                        .ok_or(BridgeError::TxHandlerNotFound)?,
                    watchtower_idx,
                    public_hash,
                    Arc::new(WinternitzCommit::new(
                        public_key,
                        winternitz_params,
                        actor.xonly_public_key,
                    )),
                    nofn_xonly_pk,
                    operator_xonly_pk,
                    config.network,
                )?
            };
            txhandlers.insert(
                watchtower_challenge_txhandler.get_transaction_type(),
                watchtower_challenge_txhandler,
            );
            // Creates the operator_challenge_NACK_tx handler.
            let operator_challenge_nack_txhandler =
                builder::transaction::create_operator_challenge_nack_txhandler(
                    txhandlers
                        .get(&TransactionType::WatchtowerChallenge(watchtower_idx))
                        .ok_or(BridgeError::TxHandlerNotFound)?,
                    watchtower_idx,
                    txhandlers
                        .get(&TransactionType::Kickoff)
                        .ok_or(BridgeError::TxHandlerNotFound)?,
                )?;
            txhandlers.insert(
                operator_challenge_nack_txhandler.get_transaction_type(),
                operator_challenge_nack_txhandler,
            );

            if let TransactionType::OperatorChallengeACK(index) = transaction_type {
                // only create this if we specifically want to generate the Operator Challenge ACK tx
                if index == watchtower_idx {
                    let operator_challenge_ack_txhandler =
                        builder::transaction::create_operator_challenge_ack_txhandler(
                            txhandlers
                                .get(&TransactionType::WatchtowerChallenge(watchtower_idx))
                                .ok_or(BridgeError::TxHandlerNotFound)?,
                            watchtower_idx,
                        )?;

                    txhandlers.insert(
                        operator_challenge_ack_txhandler.get_transaction_type(),
                        operator_challenge_ack_txhandler,
                    );
                }
            }
        }
        if transaction_type != TransactionType::AllNeededForVerifierDeposit {
            // We do not need other txhandlers, exit early
            return Ok(txhandlers);
        }
    }

    // If we didn't return until this part, generate remaining assert/disprove tx's

    if matches!(
        transaction_type,
        TransactionType::AssertBegin | TransactionType::AssertEnd | TransactionType::MiniAssert(_)
    ) {
        // if we specifically want to generate assert txs, we need to generate correct Winternitz scripts
        let actor = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );
        let mut assert_scripts = Vec::with_capacity(utils::ALL_BITVM_INTERMEDIATE_VARIABLES.len());
        for (intermediate_step, intermediate_step_size) in
            utils::ALL_BITVM_INTERMEDIATE_VARIABLES.iter()
        {
            let params = winternitz::Parameters::new(*intermediate_step_size as u32 * 2, 4);
            let path = WinternitzDerivationPath {
                message_length: *intermediate_step_size as u32 * 2,
                log_d: 4,
                tx_type: crate::actor::TxType::BitVM,
                index: Some(operator_idx as u32), // same as in operator get_params, idk why its not operator_idx
                operator_idx: None,
                watchtower_idx: None,
                sequential_collateral_tx_idx: Some(sequential_collateral_tx_idx as u32),
                kickoff_idx: Some(kickoff_idx as u32),
                intermediate_step_name: Some(intermediate_step),
            };
            let pk = actor.derive_winternitz_pk(path)?;
            assert_scripts.push(Arc::new(WinternitzCommit::new(
                pk,
                params,
                operator_xonly_pk,
            )));
        }
        // Creates the assert_begin_tx handler.
        let assert_begin_txhandler =
            builder::transaction::create_assert_begin_txhandler_from_scripts(
                txhandlers
                    .get(&TransactionType::Kickoff)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
                &assert_scripts,
                config.network,
            )?;

        txhandlers.insert(
            assert_begin_txhandler.get_transaction_type(),
            assert_begin_txhandler,
        );

        let root_hash = db
            .get_bitvm_root_hash(
                None,
                operator_idx as i32,
                sequential_collateral_tx_idx as i32,
                kickoff_idx as i32,
            )
            .await?
            .ok_or(BridgeError::BitvmSetupNotFound(
                operator_idx as i32,
                sequential_collateral_tx_idx as i32,
                kickoff_idx as i32,
            ))?;

        // Creates the assert_end_tx handler.
        let mini_asserts_and_assert_end_txhandlers =
            builder::transaction::create_mini_asserts_and_assert_end_from_scripts(
                txhandlers
                    .get(&TransactionType::Kickoff)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
                txhandlers
                    .get(&TransactionType::AssertBegin)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
                &assert_scripts,
                &root_hash,
                nofn_xonly_pk,
                config.network,
            )?;
        for txhandler in mini_asserts_and_assert_end_txhandlers {
            txhandlers.insert(txhandler.get_transaction_type(), txhandler);
        }
    } else {
        // Get the bitvm setup for this operator, sequential collateral tx, and kickoff idx.
        let (assert_tx_addrs, root_hash, _public_input_wots) = db
            .get_bitvm_setup(
                None,
                operator_idx as i32,
                sequential_collateral_tx_idx as i32,
                kickoff_idx as i32,
            )
            .await?
            .ok_or(BridgeError::BitvmSetupNotFound(
                operator_idx as i32,
                sequential_collateral_tx_idx as i32,
                kickoff_idx as i32,
            ))?;

        // Creates the assert_begin_tx handler.
        let assert_begin_txhandler = builder::transaction::create_assert_begin_txhandler(
            txhandlers
                .get(&TransactionType::Kickoff)
                .ok_or(BridgeError::TxHandlerNotFound)?,
            &assert_tx_addrs,
            config.network,
        )?;

        txhandlers.insert(
            assert_begin_txhandler.get_transaction_type(),
            assert_begin_txhandler,
        );

        // Creates the assert_end_tx handler.
        let assert_end_txhandler = builder::transaction::create_assert_end_txhandler(
            txhandlers
                .get(&TransactionType::Kickoff)
                .ok_or(BridgeError::TxHandlerNotFound)?,
            txhandlers
                .get(&TransactionType::AssertBegin)
                .ok_or(BridgeError::TxHandlerNotFound)?,
            &assert_tx_addrs,
            &root_hash,
            nofn_xonly_pk,
            config.network,
        )?;

        txhandlers.insert(
            assert_end_txhandler.get_transaction_type(),
            assert_end_txhandler,
        );
    }

    // Creates the disprove_timeout_tx handler.
    let disprove_timeout_txhandler = builder::transaction::create_disprove_timeout_txhandler(
        txhandlers
            .get(&TransactionType::AssertEnd)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        operator_xonly_pk,
        config.network,
    )?;

    txhandlers.insert(
        disprove_timeout_txhandler.get_transaction_type(),
        disprove_timeout_txhandler,
    );

    // Creates the already_disproved_tx handler.
    let already_disproved_txhandler = builder::transaction::create_already_disproved_txhandler(
        txhandlers
            .get(&TransactionType::AssertEnd)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        txhandlers
            .get(&TransactionType::SequentialCollateral)
            .ok_or(BridgeError::TxHandlerNotFound)?,
    )?;

    txhandlers.insert(
        already_disproved_txhandler.get_transaction_type(),
        already_disproved_txhandler,
    );

    // Creates the reimburse_tx handler.
    let reimburse_txhandler = builder::transaction::create_reimburse_txhandler(
        txhandlers
            .get(&TransactionType::MoveToVault)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        txhandlers
            .get(&TransactionType::DisproveTimeout)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        txhandlers
            .get(&TransactionType::ReimburseGenerator)
            .ok_or(BridgeError::TxHandlerNotFound)?,
        kickoff_idx,
        &operator_reimburse_address,
    )?;

    txhandlers.insert(
        reimburse_txhandler.get_transaction_type(),
        reimburse_txhandler,
    );

    match transaction_type {
        TransactionType::AllNeededForOperatorDeposit => {
            let disprove_txhandler = builder::transaction::create_disprove_txhandler(
                txhandlers
                    .get(&TransactionType::AssertEnd)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
                txhandlers
                    .get(&TransactionType::SequentialCollateral)
                    .ok_or(BridgeError::TxHandlerNotFound)?,
            )?;
            txhandlers.insert(
                disprove_txhandler.get_transaction_type(),
                disprove_txhandler,
            );
        }
        TransactionType::Disprove => {
            // TODO: if transactiontype::disprove, we need to add the actual disprove script here because requester wants to disprove the withdrawal
        }
        _ => {}
    }

    Ok(txhandlers)
}
