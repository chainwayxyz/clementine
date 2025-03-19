use super::common::{create_actors, create_test_config_with_thread_name, tx_utils::*};
use crate::actor::Actor;
use crate::builder::transaction::sign::get_kickoff_utxos_to_sign;
use crate::builder::transaction::TransactionType as TxType;
use crate::citrea::mock::MockCitreaClient;
use crate::config::protocol::BLOCKS_PER_HOUR;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::{
    AssertRequest, DepositParams, Empty, FinalizedPayoutParams, KickoffId, SignedTxsWithType,
    TransactionRequest,
};
use crate::test::common::*;
use crate::tx_sender::TxSenderClient;
use crate::EVMAddress;
use bitcoin::hashes::Hash;
use bitcoin::{consensus, OutPoint, Transaction, Txid, XOnlyPublicKey};
use eyre::{Context, Result};
use tonic::Request;

const BLOCKS_PER_DAY: u64 = 144;

async fn base_setup(
    config: &mut BridgeConfig,
    rpc: &ExtendedRpc,
) -> Result<
    (
        Vec<ClementineOperatorClient<tonic::transport::Channel>>,
        Vec<ClementineWatchtowerClient<tonic::transport::Channel>>,
        TxSenderClient,
        DepositParams,
        u32,
        TransactionRequest,
        SignedTxsWithType,
        ActorsCleanup,
    ),
    eyre::Error,
> {
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, watchtowers, cleanup) =
        create_actors::<MockCitreaClient>(config).await;
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };
    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = TxSenderClient::new(tx_sender_db.clone(), "run_happy_path_2".to_string());
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
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);
    let nofn_xonly_pk =
        XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)?;
    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
        nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
    };
    tracing::info!("Creating move transaction");
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();
    ensure_tx_onchain(
        rpc,
        Txid::from_byte_array(move_tx_response.txid.clone().try_into().unwrap()),
    )
    .await?;
    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);
    let op0_xonly_pk = Actor::new(
        config.all_operators_secret_keys.clone().unwrap()[0],
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .xonly_public_key;
    let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;
    let kickoff_idx = get_kickoff_utxos_to_sign(
        config.protocol_paramset(),
        op0_xonly_pk,
        deposit_blockhash,
        deposit_outpoint,
    )[0] as u32;
    let base_tx_req = TransactionRequest {
        transaction_type: Some(TxType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx,
        }),
        deposit_params: Some(dep_params.clone()),
    };
    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();
    Ok((
        operators,
        watchtowers,
        tx_sender,
        dep_params,
        kickoff_idx,
        base_tx_req,
        all_txs,
        cleanup,
    ))
}

pub async fn run_operator_end_round(
    config: BridgeConfig,
    rpc: ExtendedRpc,
    is_challenge: bool,
) -> Result<()> {
    // Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (mut verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors::<MockCitreaClient>(&config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(&config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;
    // Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let nofn_xonly_pk =
        XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)?;

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
        nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
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

    ensure_tx_onchain(&rpc, move_txid).await?;

    let kickoff_txid = operators[0]
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: [1u8; 32].to_vec(),
            deposit_outpoint: Some(deposit_outpoint.into()),
        })
        .await?;

    let kickoff_txid = Txid::from_byte_array(kickoff_txid.into_inner().txid.try_into().unwrap());

    operators[0]
        .internal_end_round(Request::new(Empty {}))
        .await?;

    ensure_tx_onchain(&rpc, kickoff_txid).await?;

    if is_challenge {
        verifiers[1]
            .internal_handle_kickoff(Request::new(crate::rpc::clementine::Txid {
                txid: kickoff_txid.to_byte_array().to_vec(),
            }))
            .await?;
    }

    let wait_to_be_spent = if is_challenge {
        OutPoint {
            txid: kickoff_txid,
            vout: 1,
        }
    } else {
        OutPoint {
            txid: move_txid,
            vout: 0,
        }
    };
    ensure_outpoint_spent(&rpc, wait_to_be_spent).await?;
    Ok(())
}

pub async fn run_happy_path_1(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting happy path test");
    config.test_params.should_run_state_manager = false;

    let (
        mut operators,
        _watchtowers,
        tx_sender,
        _dep_params,
        _kickoff_idx,
        base_tx_req,
        all_txs,
        _cleanup,
    ) = base_setup(config, &rpc).await?;

    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Wait 1 week
    rpc.mine_blocks(7 * 24 * 6).await?;

    tracing::info!("Sending challenge timeout transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::ChallengeTimeout).await?;

    // Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::ReadyToReimburse).await?;

    rpc.mine_blocks(6 * 24 * 2 + 1).await?;

    // Send Reimburse Generator 1
    tracing::info!("Sending round 2 transaction");
    let all_txs_2 = operators[0]
        .internal_create_signed_txs(TransactionRequest {
            transaction_type: Some(TxType::Round.into()),
            kickoff_id: Some(KickoffId {
                operator_idx: 0,
                round_idx: 1,
                kickoff_idx: 0,
            }),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();

    send_tx_with_type(&rpc, &tx_sender, &all_txs_2, TxType::Round).await?;

    // Send Happy Reimburse Transaction
    tracing::info!("Sending happy reimburse transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Reimburse).await?;

    tracing::info!("Reimburse transaction sent successfully");
    tracing::info!("Happy path test completed successfully");
    Ok(())
}

/// Happy Path 2 flow:
/// Setup Aggregator
/// Make a Deposit
/// Make a Withdrawal
/// Send Kickoff Transaction
/// Send Challenge Transaction
/// Send Watchtower Challenge Transactions
/// Send Operator Challenge Acknowledgment Transactions
/// Send Assert Transactions
/// Send Disprove Timeout Transaction
/// Send Reimburse Transaction
pub async fn run_happy_path_2(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Happy Path 2 test");

    let (
        mut operators,
        mut watchtowers,
        tx_sender,
        dep_params,
        kickoff_idx,
        base_tx_req,
        all_txs,
        _cleanup,
    ) = base_setup(config, &rpc).await?;

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Send Watchtower Challenge Transactions
    for (watchtower_idx, watchtower) in watchtowers.iter_mut().enumerate() {
        let watchtower_challenge_tx = watchtower
            .internal_create_watchtower_challenge(TransactionRequest {
                transaction_type: Some(TxType::WatchtowerChallenge(watchtower_idx).into()),
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
            &rpc,
            watchtower_challenge_tx.raw_tx.as_slice(),
            TxType::WatchtowerChallenge(watchtower_idx),
        )
        .await
        .context(format!(
            "failed to send watchtower challenge transaction for watchtower {}",
            watchtower_idx
        ))?;
    }

    // Send Operator Challenge Acknowledgment Transactions
    for watchtower_idx in 0..config.protocol_paramset().num_watchtowers {
        tracing::info!(
            "Sending operator challenge ack transaction for watchtower {}",
            watchtower_idx
        );
        let operator_challenge_ack_txs = operators[0]
            .internal_create_signed_txs(TransactionRequest {
                transaction_type: Some(TxType::OperatorChallengeAck(watchtower_idx).into()),
                ..base_tx_req.clone()
            })
            .await?
            .into_inner();
        send_tx_with_type(
            &rpc,
            &tx_sender,
            &operator_challenge_ack_txs,
            TxType::OperatorChallengeAck(watchtower_idx),
        )
        .await?;
    }

    // Send Assert Transactions
    // these are already sent by the state machine
    let assert_txs = operators[0]
        .internal_create_assert_commitment_txs(AssertRequest {
            deposit_params: Some(dep_params.clone()),
            kickoff_id: Some(KickoffId {
                operator_idx: 0,
                round_idx: 0,
                kickoff_idx,
            }),
        })
        .await?
        .into_inner();
    for (assert_idx, tx) in assert_txs.signed_txs.iter().enumerate() {
        tracing::info!("Sending mini assert transaction {}", assert_idx);
        send_tx(
            &tx_sender,
            &rpc,
            tx.raw_tx.as_slice(),
            TxType::MiniAssert(assert_idx),
        )
        .await
        .context(format!(
            "failed to send mini assert transaction {}",
            assert_idx
        ))?;
    }

    rpc.mine_blocks(BLOCKS_PER_DAY * 5).await?;
    // Send Disprove Timeout Transaction
    tracing::info!("Sending disprove timeout transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::DisproveTimeout).await?;

    // Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::ReadyToReimburse).await?;

    rpc.mine_blocks(6 * 24 * 2 + 1).await?;

    // Send Reimburse Generator 1
    tracing::info!("Sending round 2 transaction");
    let all_txs_2 = operators[0]
        .internal_create_signed_txs(TransactionRequest {
            transaction_type: Some(TxType::Round.into()),
            kickoff_id: Some(KickoffId {
                operator_idx: 0,
                round_idx: 1,
                kickoff_idx,
            }),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();

    // Send Round 2
    send_tx_with_type(&rpc, &tx_sender, &all_txs_2, TxType::Round).await?;

    // Send Reimburse Transaction
    tracing::info!("Sending reimburse transaction");
    let reimburse_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TxType::Reimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &rpc,
        reimburse_tx.raw_tx.as_slice(),
        TxType::Reimburse,
    )
    .await
    .context("failed to send reimburse transaction")?;

    tracing::info!("Happy Path 2 test completed successfully");
    Ok(())
}

/// Simple Assert flow without watchtower challenges/acks
pub async fn run_simple_assert_flow(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Simple Assert Flow");

    let (
        mut operators,
        _watchtowers,
        tx_sender,
        dep_params,
        kickoff_idx,
        _base_tx_req,
        all_txs,
        _cleanup,
    ) = base_setup(config, &rpc).await?;

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Directly create and send assert transactions
    tracing::info!("Creating and sending assert transactions directly");

    // Get deposit data and kickoff ID for assert creation
    let kickoff_id = KickoffId {
        operator_idx: 0,
        round_idx: 0,
        kickoff_idx,
    };

    rpc.mine_blocks(8 * BLOCKS_PER_HOUR as u64).await?;

    for i in 0..config.protocol_paramset().num_watchtowers {
        send_tx_with_type(
            &rpc,
            &tx_sender,
            &all_txs,
            TxType::WatchtowerChallengeTimeout(i),
        )
        .await?;
    }

    // Sending all timeouts should trigger the state machine to send the assert transactions

    // Create assert transactions for operator 0
    let assert_txs = operators[0]
        .internal_create_assert_commitment_txs(AssertRequest {
            kickoff_id: Some(kickoff_id),
            deposit_params: Some(dep_params.clone()),
        })
        .await?
        .into_inner();

    // Ensure all assert transactions are sent in order
    for tx in assert_txs.signed_txs.iter() {
        tracing::info!(
            "Waiting for assert transaction of type: {:?}",
            tx.transaction_type
        );
        let tx_type = tx.transaction_type.unwrap();
        let tx = consensus::deserialize::<Transaction>(tx.raw_tx.as_slice()).unwrap();
        ensure_outpoint_spent(&rpc, tx.input[0].previous_output)
            .await
            .context(format!(
                "failed to ensure assert transaction of type {:?}",
                tx_type
            ))?;
    }

    // Mine blocks to confirm transactions
    rpc.mine_blocks(10).await?;

    tracing::info!("Simple Assert Flow test completed successfully");
    Ok(())
}

/// Bad Path 1 flow:
/// Setup Aggregator
/// Make a Deposit
/// Make a Withdrawal
/// Send Kickoff Transaction
/// Send Challenge Transaction
/// Send Watchtower Challenge Transaction
/// Send Operator Challenge Negative Acknowledgment Transaction
pub async fn run_bad_path_1(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 1 test");

    let (
        _operators,
        mut watchtowers,
        tx_sender,
        _dep_params,
        _kickoff_idx,
        base_tx_req,
        all_txs,
        _cleanup,
    ) = base_setup(config, &rpc).await?;

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Send Watchtower Challenge Transaction (just for the first watchtower)
    // Send Watchtower Challenge Transactions
    let watchtower_idx = 0;
    tracing::info!(
        "Sending watchtower challenge transaction for watchtower {}",
        watchtower_idx
    );
    let watchtower_challenge_tx = watchtowers[watchtower_idx]
        .internal_create_watchtower_challenge(TransactionRequest {
            transaction_type: Some(TxType::WatchtowerChallenge(watchtower_idx).into()),
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
        &rpc,
        watchtower_challenge_tx.raw_tx.as_slice(),
        TxType::WatchtowerChallenge(watchtower_idx),
    )
    .await
    .context(format!(
        "failed to send watchtower challenge transaction for watchtower {}",
        watchtower_idx
    ))?;

    rpc.mine_blocks(BLOCKS_PER_DAY * 3).await?;

    // Send Operator Challenge Negative Acknowledgment Transaction
    tracing::info!(
        "Sending operator challenge nack transaction for watchtower {}",
        watchtower_idx
    );
    send_tx_with_type(
        &rpc,
        &tx_sender,
        &all_txs,
        TxType::OperatorChallengeNack(watchtower_idx),
    )
    .await?;

    tracing::info!("Bad Path 1 test completed successfully");
    Ok(())
}

/// Bad Path 2 flow:
/// Setup Aggregator
/// Make a Deposit
/// Make a Withdrawal
/// Send Kickoff Transaction
/// Send Challenge Transaction
/// Send Watchtower Challenge Transaction
/// Send Operator Challenge Acknowledgment Transaction
/// Send Kickoff Timeout Transaction
pub async fn run_bad_path_2(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 2 test");

    let (
        _operators,
        _watchtowers,
        tx_sender,
        _dep_params,
        _kickoff_idx,
        _base_tx_req,
        all_txs,
        _cleanup,
    ) = base_setup(config, &rpc).await?;

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction

    // Send Challenge Transaction
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Ready to reimburse without finalized kickoff
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::ReadyToReimburse).await?;

    // Kickoff is not finalized, burn
    tracing::info!("Sending kickoff not finalized transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::KickoffNotFinalized).await?;

    tracing::info!("Bad Path 2 test completed successfully");
    Ok(())
}

/// Bad Path 3 flow:
/// Setup Aggregator
/// Make a Deposit
/// Make a Withdrawal
/// Send Kickoff Transaction
/// Send Challenge Transaction
/// Send Watchtower Challenge Transactions
/// Send Operator Challenge Acknowledgment Transactions
/// Send Assert Transactions
/// Send Disprove Transaction
pub async fn run_bad_path_3(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 3 test");

    let (
        _operators,
        _watchtowers,
        tx_sender,
        _dep_params,
        _kickoff_idx,
        _base_tx_req,
        all_txs,
        _cleanup,
    ) = base_setup(config, &rpc).await?;

    // Send Round Transaction
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Send Watchtower Challenge Transactions
    for watchtower_idx in 0..config.protocol_paramset().num_watchtowers {
        tracing::info!(
            "Sending watchtower challenge transaction for watchtower {}",
            watchtower_idx
        );
        send_tx_with_type(
            &rpc,
            &tx_sender,
            &all_txs,
            TxType::WatchtowerChallenge(watchtower_idx),
        )
        .await?;
    }

    // Send Operator Challenge Acknowledgment Transactions
    for watchtower_idx in 0..config.protocol_paramset().num_watchtowers {
        tracing::info!(
            "Sending operator challenge ack transaction for watchtower {}",
            watchtower_idx
        );
        send_tx_with_type(
            &rpc,
            &tx_sender,
            &all_txs,
            TxType::OperatorChallengeAck(watchtower_idx),
        )
        .await?;
    }

    // Send Assert Transactions
    let num_asserts = crate::bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs();
    for assert_idx in 0..num_asserts {
        tracing::info!("Sending mini assert transaction {}", assert_idx);
        send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::MiniAssert(assert_idx)).await?;
    }

    // Send Disprove Transaction
    tracing::info!("Sending disprove transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Disprove).await?;

    tracing::info!("Bad Path 3 test completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_simple_assert_flow() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_simple_assert_flow(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    // #[ignore = "Design changes in progress"]
    async fn test_happy_path_1() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path_1(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_happy_path_2() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path_2(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_path_1() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_1(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_path_2() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_2(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "Assert is not ready"]
    async fn test_bad_path_3() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_3(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_operator_end_round() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_operator_end_round(config, rpc, false).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_operator_end_round_with_challenge() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_operator_end_round(config, rpc, true).await.unwrap();
    }
}
