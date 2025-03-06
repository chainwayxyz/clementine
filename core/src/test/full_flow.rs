use super::common::{create_actors, create_test_config_with_thread_name};
use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::transaction::TransactionType;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::FinalizedPayoutParams;
use crate::rpc::clementine::{DepositParams, Empty, KickoffId, TransactionRequest};
use crate::test::common::*;
use crate::tx_sender::{FeePayingType, TxDataForLogging, TxSender};
use crate::EVMAddress;
use bitcoin::consensus::{self};
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use eyre::{bail, Context, Result};
use secp256k1::rand::rngs::ThreadRng;
use tonic::Request;

const BLOCKS_PER_DAY: u64 = 144;

pub async fn run_operator_end_round(config: BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors(&config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(&config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;
    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    let move_txid: bitcoin::Txid =
        bitcoin::Txid::from_byte_array(move_tx_response.txid.try_into().unwrap());

    tracing::info!(
        "Move transaction sent, waiting for on-chain confirmation: {:x?}",
        move_txid
    );

    // Try for 60 iterations (approximately 6 seconds plus mining time)
    for attempt in 0..60 {
        tracing::info!(
            "Checking if move tx is confirmed (attempt {}/60)",
            attempt + 1
        );
        let spent = rpc.client.get_raw_transaction_info(&move_txid, None).await;

        if spent.is_err() {
            tracing::error!("Move tx not found");
        } else if spent.unwrap().blockhash.is_some() {
            break;
        }

        // If this is the last attempt and we haven't broken out of the loop yet
        if attempt == 59 {
            return Err(eyre::eyre!("Timeout waiting for move tx confirmation"));
        }

        rpc.mine_blocks(1).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    operators[0]
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: [1u8; 32].to_vec(),
            deposit_outpoint: Some(deposit_outpoint.into()),
        })
        .await?;

    rpc.mine_blocks(1).await?;

    operators[0]
        .internal_end_round(Request::new(Empty {}))
        .await?;

    // Try for 60 iterations (approximately 6 seconds plus mining time)
    for attempt in 0..2000 {
        tracing::info!("Checking if move tx is spent (attempt {}/60)", attempt + 1);
        // check if the move_tx is spent
        let spent = rpc.client.get_tx_out(&move_txid, 0, Some(true)).await?;
        if spent.is_none() {
            break;
        }

        // If this is the last attempt and we haven't broken out of the loop yet
        if attempt == 2000 - 1 {
            return Err(eyre::eyre!("Timeout waiting for move tx to be spent"));
        }

        rpc.mine_blocks(1).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(())
}

pub async fn run_operator_end_round_with_challenge(
    config: BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<()> {
    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (mut verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors(&config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(&config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;
    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    let move_txid: bitcoin::Txid =
        bitcoin::Txid::from_byte_array(move_tx_response.txid.try_into().unwrap());

    tracing::info!(
        "Move transaction sent, waiting for on-chain confirmation: {:x?}",
        move_txid
    );

    // Try for 60 iterations (approximately 6 seconds plus mining time)
    for attempt in 0..60 {
        tracing::info!(
            "Checking if move tx is confirmed (attempt {}/60)",
            attempt + 1
        );
        let spent = rpc.client.get_raw_transaction_info(&move_txid, None).await;

        if spent.is_err() {
            tracing::error!("Move tx not found");
        } else if spent.unwrap().blockhash.is_some() {
            break;
        }

        // If this is the last attempt and we haven't broken out of the loop yet
        if attempt == 59 {
            return Err(eyre::eyre!("Timeout waiting for move tx confirmation"));
        }

        rpc.mine_blocks(1).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let kickoff_txid = operators[0]
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: [1u8; 32].to_vec(),
            deposit_outpoint: Some(deposit_outpoint.into()),
        })
        .await?;

    rpc.mine_blocks(1).await?;

    verifiers[0]
        .internal_handle_kickoff(Request::new(kickoff_txid.into_inner()))
        .await?;

    rpc.mine_blocks(1).await?;

    operators[0]
        .internal_end_round(Request::new(Empty {}))
        .await?;

    // Try for 60 iterations (approximately 6 seconds plus mining time)
    for attempt in 0..2000 {
        tracing::info!("Checking if move tx is spent (attempt {}/60)", attempt + 1);
        // check if the move_tx is spent
        let spent = rpc.client.get_tx_out(&move_txid, 0, Some(true)).await?;
        if spent.is_none() {
            break;
        }

        // If this is the last attempt and we haven't broken out of the loop yet
        if attempt == 2000 - 1 {
            return Err(eyre::eyre!("Timeout waiting for move tx to be spent"));
        }

        rpc.mine_blocks(1).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(())
}


pub async fn run_happy_path_1(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting happy path test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors(config).await;

    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    tracing::info!("verifier_0_config: {:#?}", verifier_0_config);

    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = {
        let actor = Actor::new(
            keypair.secret_key(),
            None,
            config.protocol_paramset().network,
        );

        // This tx sender will be adding txs using verifier 0's tx sender loop
        TxSender::new(
            actor.clone(),
            rpc.clone(),
            tx_sender_db.clone(),
            "run_happy_path_1",
            config.protocol_paramset().network,
        )
    };

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;

    let withdrawal_amount = config.protocol_paramset().bridge_amount.to_sat()
        - (2 * config
            .operator_withdrawal_fee_sats
            .expect("exists in test config")
            .to_sat());
    tracing::info!("Withdrawal amount set to: {} sats", withdrawal_amount);

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);

    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
    };

    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    tracing::info!("Sending round transaction");
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_tx.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round transaction")?;

    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_tx.raw_tx.as_slice(),
        TransactionType::Kickoff,
    )
    .await
    .context("failed to send kickoff transaction")?;

    // Wait 1 week
    rpc.mine_blocks(7 * 24 * 6).await?;

    tracing::info!("Sending challenge timeout transaction");
    let challenge_timeout_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::ChallengeTimeout.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        challenge_timeout_tx.raw_tx.as_slice(),
        TransactionType::ChallengeTimeout,
    )
    .await
    .context("failed to send challenge timeout transaction")?;

    // 7. Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse transaction");
    let ready_to_reimburse = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::ReadyToReimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        ready_to_reimburse.raw_tx.as_slice(),
        TransactionType::ReadyToReimburse,
    )
    .await
    .context("failed to send ready to reimburse transaction")?;

    rpc.mine_blocks(6 * 24 * 2 + 1).await?;

    // 8. Send Reimburse Generator 1
    tracing::info!("Sending round 2 transaction");
    let all_txs_2 = operators[0]
        .internal_create_signed_txs(TransactionRequest {
            transaction_type: Some(TransactionType::Round.into()),
            kickoff_id: Some(KickoffId {
                operator_idx: 0,
                round_idx: 1,
                kickoff_idx: 0,
            }),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();

    let round_2 = all_txs_2
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_2.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round 2 transaction")?;

    // 8. Send Happy Reimburse Transaction
    tracing::info!("Sending happy reimburse transaction");
    let reimburse_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Reimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        reimburse_tx.raw_tx.as_slice(),
        TransactionType::Reimburse,
    )
    .await
    .context("failed to send reimburse transaction")?;

    tracing::info!("Reimburse transaction sent successfully");
    tracing::info!("Happy path test completed successfully");
    Ok(())
}

// Helper function to send a transaction and mine a block
pub async fn send_tx(
    tx_sender: &TxSender,
    db: &Database,
    rpc: &ExtendedRpc,
    raw_tx: &[u8],
    tx_type: TransactionType,
) -> Result<()> {
    let tx: Transaction = consensus::deserialize(raw_tx).context("expected valid tx")?;
    let mut dbtx = db.begin_transaction().await?;

    // Try to send the transaction with CPFP first
    let send_result = tx_sender
        .try_to_send(
            &mut dbtx,
            Some(TxDataForLogging {
                tx_type,
                deposit_outpoint: None,
                kickoff_idx: None,
                operator_idx: None,
                round_idx: None,
                verifier_idx: None,
            }),
            &tx,
            FeePayingType::CPFP,
            &[],
            &[],
            &[],
            &[],
        )
        .await;

    // If CPFP fails, try with RBF
    if let Err(e) = send_result {
        tracing::warn!("Failed to send with CPFP, trying RBF: {}", e);
        tx_sender
            .try_to_send(&mut dbtx, None, &tx, FeePayingType::RBF, &[], &[], &[], &[])
            .await?;
    }

    dbtx.commit().await?;

    // Mine blocks to confirm the transaction
    rpc.mine_blocks(3).await?;

    ensure_tx_onchain(rpc, tx.compute_txid()).await?;

    Ok(())
}

async fn ensure_tx_onchain(rpc: &ExtendedRpc, tx: Txid) -> Result<(), eyre::Error> {
    let mut timeout_counter = 40;
    while rpc
        .client
        .get_raw_transaction_info(&tx, None)
        .await
        .ok()
        .and_then(|s| s.blockhash)
        .is_none()
    {
        // Mine more blocks and wait longer between checks
        rpc.mine_blocks(2).await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        timeout_counter -= 1;

        if timeout_counter == 0 {
            bail!("timeout while trying to send tx with txid {:?}", tx);
        }
    }
    Ok(())
}

/// Happy Path 2 flow:
/// 1. Setup Aggregator
/// 2. Make a Deposit
/// 3. Make a Withdrawal
/// 4. Send Kickoff Transaction
/// 5. Send Challenge Transaction
/// 6. Send Watchtower Challenge Transactions
/// 7. Send Operator Challenge Acknowledgment Transactions
/// 8. Send Assert Transactions
/// 9. Send Disprove Timeout Transaction
/// 10. Send Reimburse Transaction
pub async fn run_happy_path_2(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Happy Path 2 test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, mut watchtowers, _cleanup) =
        create_actors(config).await;

    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    // Setup tx_sender for sending transactions
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = {
        let actor = Actor::new(
            keypair.secret_key(),
            None,
            config.protocol_paramset().network,
        );

        TxSender::new(
            actor.clone(),
            rpc.clone(),
            tx_sender_db.clone(),
            "run_happy_path_2",
            config.protocol_paramset().network,
        )
    };

    // Generate deposit address
    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;

    let withdrawal_amount = config.protocol_paramset().bridge_amount.to_sat()
        - (2 * config
            .operator_withdrawal_fee_sats
            .expect("exists in test config")
            .to_sat());
    tracing::info!("Withdrawal amount set to: {} sats", withdrawal_amount);

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    ensure_tx_onchain(
        &rpc,
        Txid::from_byte_array(move_tx_response.txid.clone().try_into().unwrap()),
    )
    .await?;
    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);

    // 4. Create and send all transactions for the flow
    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
    };

    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    // 5. Send Round Transaction
    tracing::info!("Sending round transaction");
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_tx.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round transaction")?;

    // 6. Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_tx.raw_tx.as_slice(),
        TransactionType::Kickoff,
    )
    .await
    .context("failed to send kickoff transaction")?;

    // 7. Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    // Add later when RBF is implemented
    // let challenge_tx = all_txs
    //     .signed_txs
    //     .iter()
    //     .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
    //     .unwrap();
    // send_tx(
    //     &tx_sender,
    //     &tx_sender_db,
    //     &rpc,
    //     challenge_tx.raw_tx.as_slice(),
    // )
    // .await
    // .context("failed to send challenge transaction")?;

    // 8. Send Watchtower Challenge Transactions
    for (watchtower_idx, watchtower) in watchtowers.iter_mut().enumerate() {
        let watchtower_challenge_tx = watchtower
            .internal_create_watchtower_challenge(TransactionRequest {
                transaction_type: Some(TransactionType::WatchtowerChallenge(watchtower_idx).into()),
                ..base_tx_req.clone()
            })
            .await?
            .into_inner();
        tracing::info!(
            "Sending watchtower challenge transaction for watchtower {}",
            watchtower_idx
        );

        send_tx(
            &tx_sender,
            &tx_sender_db,
            &rpc,
            watchtower_challenge_tx.raw_tx.as_slice(),
            TransactionType::WatchtowerChallenge(watchtower_idx),
        )
        .await
        .context(format!(
            "failed to send watchtower challenge transaction for watchtower {}",
            watchtower_idx
        ))?;
    }

    // 9. Send Operator Challenge Acknowledgment Transactions
    for watchtower_idx in 0..config.protocol_paramset().num_watchtowers {
        tracing::info!(
            "Sending operator challenge ack transaction for watchtower {}",
            watchtower_idx
        );
        let operator_challenge_ack_txs = operators[0]
            .internal_create_signed_txs(TransactionRequest {
                transaction_type: Some(
                    TransactionType::OperatorChallengeAck(watchtower_idx).into(),
                ),
                ..base_tx_req.clone()
            })
            .await?
            .into_inner();
        let operator_challenge_ack_tx = operator_challenge_ack_txs
            .signed_txs
            .iter()
            .find(|tx| {
                tx.transaction_type
                    == Some(TransactionType::OperatorChallengeAck(watchtower_idx).into())
            })
            .unwrap();
        send_tx(
            &tx_sender,
            &tx_sender_db,
            &rpc,
            operator_challenge_ack_tx.raw_tx.as_slice(),
            TransactionType::OperatorChallengeAck(watchtower_idx),
        )
        .await
        .context(format!(
            "failed to send operator challenge ack transaction for watchtower {}",
            watchtower_idx
        ))?;
    }

    // 10. Send Assert Transactions
    // TODO: Add assert transactions
    // let assert_txs = operators[0]
    //     .internal_create_assert_commitment_txs(AssertRequest {
    //         deposit_params: Some(dep_params.clone()),
    //         kickoff_id: Some(KickoffId {
    //             operator_idx: 0,
    //             round_idx: 0,
    //             kickoff_idx: 0,
    //         }),
    //     })
    //     .await?
    //     .into_inner();
    // for (assert_idx, tx) in assert_txs.raw_txs.iter().enumerate() {
    //     tracing::info!("Sending mini assert transaction {}", assert_idx);
    //      send_tx(&tx_sender, &tx_sender_db, &rpc, &tx.raw_tx)
    //         .await
    //         .context(format!(
    //             "failed to send mini assert transaction {}",
    //             assert_idx
    //         ))?;
    // }

    rpc.mine_blocks(BLOCKS_PER_DAY * 5).await?;
    // 11. Send Disprove Timeout Transaction
    tracing::info!("Sending disprove timeout transaction");
    let disprove_timeout_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::DisproveTimeout.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        disprove_timeout_tx.raw_tx.as_slice(),
        TransactionType::DisproveTimeout,
    )
    .await
    .context("failed to send disprove timeout transaction")?;

    // 12. Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse transaction");
    let ready_to_reimburse = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::ReadyToReimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        ready_to_reimburse.raw_tx.as_slice(),
        TransactionType::ReadyToReimburse,
    )
    .await
    .context("failed to send ready to reimburse transaction")?;

    rpc.mine_blocks(6 * 24 * 2 + 1).await?;

    // 8. Send Reimburse Generator 1
    tracing::info!("Sending round 2 transaction");
    let all_txs_2 = operators[0]
        .internal_create_signed_txs(TransactionRequest {
            transaction_type: Some(TransactionType::Round.into()),
            kickoff_id: Some(KickoffId {
                operator_idx: 0,
                round_idx: 1,
                kickoff_idx: 0,
            }),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();

    let round_2 = all_txs_2
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_2.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round 2 transaction")?;

    // 12. Send Reimburse Transaction
    tracing::info!("Sending reimburse transaction");
    let reimburse_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Reimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        reimburse_tx.raw_tx.as_slice(),
        TransactionType::Reimburse,
    )
    .await
    .context("failed to send reimburse transaction")?;

    // 10. Wait for timeout period and send Kickoff Not Finalized Transaction
    tracing::info!("Mining blocks to simulate timeout period");
    // Mine a reasonable number of blocks to simulate timeout
    // tracing::info!("Sending kickoff not finalized transaction");
    // let kickoff_not_finalized_tx = all_txs
    //     .signed_txs
    //     .iter()
    //     .find(|tx| tx.transaction_type == Some(TransactionType::KickoffNotFinalized.into()))
    //     .unwrap();
    // send_tx(
    //     &tx_sender,
    //     &tx_sender_db,
    //     &rpc,
    //     kickoff_not_finalized_tx.raw_tx.as_slice(),
    // )
    // .await
    // .context("failed to send kickoff not finalized transaction")?;

    tracing::info!("Happy Path 2 test completed successfully");
    Ok(())
}

/// Bad Path 1 flow:
/// 1. Setup Aggregator
/// 2. Make a Deposit
/// 3. Make a Withdrawal
/// 4. Send Kickoff Transaction
/// 5. Send Challenge Transaction
/// 6. Send Watchtower Challenge Transaction
/// 7. Send Operator Challenge Negative Acknowledgment Transaction
pub async fn run_bad_path_1(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 1 test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, mut watchtowers, _cleanup) =
        create_actors(config).await;

    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    // Setup tx_sender for sending transactions
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = {
        let actor = Actor::new(
            keypair.secret_key(),
            None,
            config.protocol_paramset().network,
        );

        TxSender::new(
            actor.clone(),
            rpc.clone(),
            tx_sender_db.clone(),
            "run_bad_path_1",
            config.protocol_paramset().network,
        )
    };

    // Generate deposit address
    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();
    ensure_tx_onchain(
        &rpc,
        Txid::from_byte_array(move_tx_response.txid.clone().try_into().unwrap()),
    )
    .await?;
    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);

    // 4. Create and send all transactions for the flow
    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
    };

    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    // 5. Send Round Transaction
    tracing::info!("Sending round transaction");
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_tx.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round transaction")?;

    // 6. Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_tx.raw_tx.as_slice(),
        TransactionType::Kickoff,
    )
    .await
    .context("failed to send kickoff transaction")?;

    // 7. Send Challenge Transaction
    // tracing::info!("Sending challenge transaction");
    // let challenge_tx = all_txs
    //     .signed_txs
    //     .iter()
    //     .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
    //     .unwrap();
    // send_tx(
    //     &tx_sender,
    //     &tx_sender_db,
    //     &rpc,
    //     challenge_tx.raw_tx.as_slice(),
    // )
    // .await
    // .context("failed to send challenge transaction")?;

    // 8. Send Watchtower Challenge Transaction (just for the first watchtower)
    // 8. Send Watchtower Challenge Transactions
    let watchtower_idx = 0;
    tracing::info!(
        "Sending watchtower challenge transaction for watchtower {}",
        watchtower_idx
    );
    let watchtower_challenge_tx = watchtowers[watchtower_idx]
        .internal_create_watchtower_challenge(TransactionRequest {
            transaction_type: Some(TransactionType::WatchtowerChallenge(watchtower_idx).into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    tracing::info!(
        "Sending watchtower challenge transaction for watchtower {}",
        watchtower_idx
    );

    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        watchtower_challenge_tx.raw_tx.as_slice(),
        TransactionType::WatchtowerChallenge(watchtower_idx),
    )
    .await
    .context(format!(
        "failed to send watchtower challenge transaction for watchtower {}",
        watchtower_idx
    ))?;

    rpc.mine_blocks(BLOCKS_PER_DAY * 3).await?;

    // 9. Send Operator Challenge Negative Acknowledgment Transaction
    tracing::info!(
        "Sending operator challenge nack transaction for watchtower {}",
        watchtower_idx
    );
    let operator_challenge_nack_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| {
            tx.transaction_type
                == Some(TransactionType::OperatorChallengeNack(watchtower_idx).into())
        })
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        operator_challenge_nack_tx.raw_tx.as_slice(),
        TransactionType::OperatorChallengeNack(watchtower_idx),
    )
    .await
    .context(format!(
        "failed to send operator challenge nack transaction for watchtower {}",
        watchtower_idx
    ))?;

    tracing::info!("Bad Path 1 test completed successfully");
    Ok(())
}

/// Bad Path 2 flow:
/// 1. Setup Aggregator
/// 2. Make a Deposit
/// 3. Make a Withdrawal
/// 4. Send Kickoff Transaction
/// 5. Send Challenge Transaction
/// 6. Send Watchtower Challenge Transaction
/// 7. Send Operator Challenge Acknowledgment Transaction
/// 8. Send Kickoff Timeout Transaction
pub async fn run_bad_path_2(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 2 test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors(config).await;

    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    // Setup tx_sender for sending transactions
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = {
        let actor = Actor::new(
            keypair.secret_key(),
            None,
            config.protocol_paramset().network,
        );

        TxSender::new(
            actor.clone(),
            rpc.clone(),
            tx_sender_db.clone(),
            "run_bad_path_2",
            config.protocol_paramset().network,
        )
    };

    // Generate deposit address
    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();
    ensure_tx_onchain(
        &rpc,
        Txid::from_byte_array(move_tx_response.txid.clone().try_into().unwrap()),
    )
    .await?;
    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);

    // 4. Create and send all transactions for the flow
    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
    };

    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    // 5. Send Round Transaction
    tracing::info!("Sending round transaction");
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_tx.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round transaction")?;

    // 6. Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_tx.raw_tx.as_slice(),
        TransactionType::Kickoff,
    )
    .await
    .context("failed to send kickoff transaction")?;

    // 7. Send Challenge Transaction
    // TODO: Add challenge transaction
    // tracing::info!("Sending challenge transaction");
    // let challenge_tx = all_txs
    //     .signed_txs
    //     .iter()
    //     .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
    //     .unwrap();
    // send_tx(
    //     &tx_sender,
    //     &tx_sender_db,
    //     &rpc,
    //     challenge_tx.raw_tx.as_slice(),
    // )
    // .await
    // .context("failed to send challenge transaction")?;

    // Ready to reimburse without finalized kickoff
    let ready_to_reimburse_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::ReadyToReimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        ready_to_reimburse_tx.raw_tx.as_slice(),
        TransactionType::ReadyToReimburse,
    )
    .await
    .context("failed to send ready to reimburse transaction")?;

    // Kickoff is not finalized, burn
    tracing::info!("Sending kickoff not finalized transaction");
    let kickoff_not_finalized_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::KickoffNotFinalized.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_not_finalized_tx.raw_tx.as_slice(),
        TransactionType::KickoffNotFinalized,
    )
    .await
    .context("failed to send kickoff not finalized transaction")?;

    tracing::info!("Bad Path 2 test completed successfully");
    Ok(())
}

/// Bad Path 3 flow:
/// 1. Setup Aggregator
/// 2. Make a Deposit
/// 3. Make a Withdrawal
/// 4. Send Kickoff Transaction
/// 5. Send Challenge Transaction
/// 6. Send Watchtower Challenge Transactions
/// 7. Send Operator Challenge Acknowledgment Transactions
/// 8. Send Assert Transactions
/// 9. Send Disprove Transaction
pub async fn run_bad_path_3(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 3 test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors(config).await;

    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    // Setup tx_sender for sending transactions
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = {
        let actor = Actor::new(
            keypair.secret_key(),
            None,
            config.protocol_paramset().network,
        );

        TxSender::new(
            actor.clone(),
            rpc.clone(),
            tx_sender_db.clone(),
            "run_bad_path_3",
            config.protocol_paramset().network,
        )
    };

    // Generate deposit address
    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();
    ensure_tx_onchain(
        &rpc,
        Txid::from_byte_array(move_tx_response.txid.clone().try_into().unwrap()),
    )
    .await?;
    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);

    // 4. Create and send all transactions for the flow
    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
    };

    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    // 5. Send Round Transaction
    tracing::info!("Sending round transaction");
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        round_tx.raw_tx.as_slice(),
        TransactionType::Round,
    )
    .await
    .context("failed to send round transaction")?;

    // 6. Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_tx.raw_tx.as_slice(),
        TransactionType::Kickoff,
    )
    .await
    .context("failed to send kickoff transaction")?;

    // 7. Send Challenge Transaction
    // tracing::info!("Sending challenge transaction");
    // let challenge_tx = all_txs
    //     .signed_txs
    //     .iter()
    //     .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
    //     .unwrap();
    // send_tx(
    //     &tx_sender,
    //     &tx_sender_db,
    //     &rpc,
    //     challenge_tx.raw_tx.as_slice(),
    // )
    // .await
    // .context("failed to send challenge transaction")?;

    // 8. Send Watchtower Challenge Transactions
    for watchtower_idx in 0..config.protocol_paramset().num_watchtowers {
        tracing::info!(
            "Sending watchtower challenge transaction for watchtower {}",
            watchtower_idx
        );
        let watchtower_challenge_tx = all_txs
            .signed_txs
            .iter()
            .find(|tx| {
                tx.transaction_type
                    == Some(TransactionType::WatchtowerChallenge(watchtower_idx).into())
            })
            .unwrap();
        send_tx(
            &tx_sender,
            &tx_sender_db,
            &rpc,
            watchtower_challenge_tx.raw_tx.as_slice(),
            TransactionType::WatchtowerChallenge(watchtower_idx),
        )
        .await
        .context(format!(
            "failed to send watchtower challenge transaction for watchtower {}",
            watchtower_idx
        ))?;
    }

    // 9. Send Operator Challenge Acknowledgment Transactions
    for watchtower_idx in 0..config.protocol_paramset().num_watchtowers {
        tracing::info!(
            "Sending operator challenge ack transaction for watchtower {}",
            watchtower_idx
        );
        let operator_challenge_ack_tx = all_txs
            .signed_txs
            .iter()
            .find(|tx| {
                tx.transaction_type
                    == Some(TransactionType::OperatorChallengeAck(watchtower_idx).into())
            })
            .unwrap();
        send_tx(
            &tx_sender,
            &tx_sender_db,
            &rpc,
            operator_challenge_ack_tx.raw_tx.as_slice(),
            TransactionType::OperatorChallengeAck(watchtower_idx),
        )
        .await
        .context(format!(
            "failed to send operator challenge ack transaction for watchtower {}",
            watchtower_idx
        ))?;
    }

    // 10. Send Assert Transactions
    let num_asserts = crate::bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs();
    for assert_idx in 0..num_asserts {
        tracing::info!("Sending mini assert transaction {}", assert_idx);
        let mini_assert_tx = all_txs
            .signed_txs
            .iter()
            .find(|tx| tx.transaction_type == Some(TransactionType::MiniAssert(assert_idx).into()))
            .unwrap();
        send_tx(
            &tx_sender,
            &tx_sender_db,
            &rpc,
            mini_assert_tx.raw_tx.as_slice(),
            TransactionType::MiniAssert(assert_idx),
        )
        .await
        .context(format!(
            "failed to send mini assert transaction {}",
            assert_idx
        ))?;
    }

    // 11. Send Disprove Transaction
    tracing::info!("Sending disprove transaction");
    let disprove_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Disprove.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        disprove_tx.raw_tx.as_slice(),
        TransactionType::Disprove,
    )
    .await
    .context("failed to send disprove transaction")?;

    tracing::info!("Bad Path 3 test completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_happy_path_2() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path_2(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_path_1() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_1(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_path_2() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_2(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "Assert is not ready"]
    async fn test_bad_path_3() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_3(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    // #[ignore = "Design changes in progress"]
    async fn test_happy_path_1() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path_1(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_operator_end_round() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_operator_end_round(config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_operator_end_round_with_challenge() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_operator_end_round_with_challenge(config, rpc)
            .await
            .unwrap();
    }
}
