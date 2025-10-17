//! # Flow Tests
//!
//! This module contains tests that simulate typical flows of Clementine.

use super::common::test_actors::TestActors;
use super::common::{create_test_config_with_thread_name, tx_utils::*};
use crate::actor::Actor;
use crate::builder::transaction::sign::get_kickoff_utxos_to_sign;
use crate::builder::transaction::TransactionType as TxType;
use crate::config::protocol::BLOCKS_PER_HOUR;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{DepositInfo, KickoffData};
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::operator::RoundIndex;
use crate::rpc::clementine::{Empty, FinalizedPayoutParams, SignedTxsWithType, TransactionRequest};
use crate::test::common::citrea::MockCitreaClient;
use crate::test::common::*;
use crate::tx_sender::TxSenderClient;
use crate::utils::RbfSigningInfo;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid, XOnlyPublicKey};
use eyre::{Context, Result};
use tonic::Request;

const BLOCKS_PER_DAY: u64 = 144;

/// Makes a deposit and returns the necessary clients and parameters for further testing.
async fn base_setup(
    config: &mut BridgeConfig,
    rpc: &ExtendedBitcoinRpc,
) -> Result<
    (
        TestActors<MockCitreaClient>,
        Vec<TxSenderClient>,
        DepositInfo,
        u32,
        TransactionRequest,
        SignedTxsWithType,
        XOnlyPublicKey,
    ),
    eyre::Error,
> {
    let (actors, deposit_info, _move_txid, deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(config, rpc.clone(), None, None, None).await?;
    let deposit_outpoint = deposit_info.deposit_outpoint;

    let mut tx_senders = Vec::new();
    for i in 0..actors.get_num_verifiers() {
        let verifier_config = {
            let mut config = config.clone();
            config.db_name += &i.to_string();
            config
        };
        let tx_sender_db = Database::new(&verifier_config)
            .await
            .expect("failed to create database");

        let tx_sender = TxSenderClient::new(tx_sender_db.clone(), format!("full_flow_{i}"));
        tx_senders.push(tx_sender);
    }

    let op0_xonly_pk = Actor::new(
        config
            .test_params
            .all_operators_secret_keys
            .first()
            .cloned()
            .unwrap(),
        config.protocol_paramset().network,
    )
    .xonly_public_key;
    let kickoff_idx = get_kickoff_utxos_to_sign(
        config.protocol_paramset(),
        op0_xonly_pk,
        deposit_blockhash,
        deposit_outpoint,
    )[0] as u32;
    let base_tx_req = TransactionRequest {
        kickoff_id: Some(
            KickoffData {
                operator_xonly_pk: op0_xonly_pk,
                round_idx: RoundIndex::Round(0),
                kickoff_idx,
            }
            .into(),
        ),
        deposit_outpoint: Some(deposit_outpoint.into()),
    };
    let mut operator0 = actors.get_operator_client_by_index(0);
    let all_txs = operator0
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    Ok((
        actors,
        tx_senders,
        deposit_info,
        kickoff_idx,
        base_tx_req,
        all_txs,
        op0_xonly_pk,
    ))
}

pub async fn run_operator_end_round(
    config: &mut BridgeConfig,
    rpc: ExtendedBitcoinRpc,
    is_challenge: bool,
) -> Result<()> {
    let (actors, deposit_info, move_txid, _deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(config, rpc.clone(), None, None, None).await?;
    let deposit_outpoint = deposit_info.deposit_outpoint;

    let mut operator0 = actors.get_operator_client_by_index(0);
    let kickoff_txid = operator0
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: [1u8; 32].to_vec(),
            deposit_outpoint: Some(deposit_outpoint.into()),
        })
        .await?;

    let kickoff_txid = Txid::from_byte_array(kickoff_txid.into_inner().txid.try_into().unwrap());

    let mut operator0 = actors.get_operator_client_by_index(0);
    let mut verifier1 = actors.get_verifier_client_by_index(1);

    operator0.internal_end_round(Request::new(Empty {})).await?;

    ensure_tx_onchain(&rpc, kickoff_txid).await?;

    if is_challenge {
        verifier1
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

pub async fn run_happy_path_1(config: &mut BridgeConfig, rpc: ExtendedBitcoinRpc) -> Result<()> {
    tracing::info!("Starting happy path test");

    let (actors, tx_senders, _dep_params, _kickoff_idx, base_tx_req, all_txs, op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

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
    let mut operator0 = actors.get_operator_client_by_index(0);
    let all_txs_2 = operator0
        .internal_create_signed_txs(TransactionRequest {
            kickoff_id: Some(
                KickoffData {
                    operator_xonly_pk: op0_xonly_pk,
                    round_idx: RoundIndex::Round(1),
                    kickoff_idx: 0,
                }
                .into(),
            ),
            ..base_tx_req
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
pub async fn run_happy_path_2(config: &mut BridgeConfig, rpc: ExtendedBitcoinRpc) -> Result<()> {
    tracing::info!("Starting Happy Path 2 test");

    let (actors, tx_senders, _deposit_info, _kickoff_idx, base_tx_req, all_txs, op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

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
    for (verifier_idx, verifier) in actors.get_verifiers().iter_mut().enumerate() {
        let watchtower_challenge_tx = verifier
            .internal_create_watchtower_challenge(base_tx_req.clone())
            .await?
            .into_inner();
        tracing::warn!(
            "Sending watchtower challenge transaction for watchtower {}",
            verifier_idx
        );
        let rbf_info: Option<RbfSigningInfo> = watchtower_challenge_tx
            .rbf_info
            .map(|rbf_rpc| rbf_rpc.try_into().unwrap());

        tracing::warn!("Watchtower challenge rbf info: {:?}", rbf_info);

        send_tx(
            &tx_senders[verifier_idx].clone(),
            &rpc,
            watchtower_challenge_tx.raw_tx.as_slice(),
            TxType::WatchtowerChallenge(verifier_idx),
            rbf_info,
        )
        .await
        .context(format!(
            "failed to send watchtower challenge transaction for watchtower {verifier_idx}"
        ))?;
    }

    // Send Operator Challenge Acknowledgment Transactions
    for verifier_idx in 0..actors.get_num_verifiers() {
        tracing::info!(
            "Sending operator challenge ack transaction for verifier {}",
            verifier_idx
        );
        let mut operator0 = actors.get_operator_client_by_index(0);
        let operator_challenge_ack_txs = operator0
            .internal_create_signed_txs(base_tx_req.clone())
            .await?
            .into_inner();
        send_tx_with_type(
            &rpc,
            &tx_sender,
            &operator_challenge_ack_txs,
            TxType::OperatorChallengeAck(verifier_idx),
        )
        .await?;
    }

    // Send Assert Transactions
    let mut operator0 = actors.get_operator_client_by_index(0);
    let assert_txs = operator0
        .internal_create_assert_commitment_txs(base_tx_req.clone())
        .await?
        .into_inner();
    for (assert_idx, tx) in assert_txs.signed_txs.iter().enumerate() {
        tracing::info!("Sending mini assert transaction {}", assert_idx);
        send_tx(
            &tx_sender,
            &rpc,
            tx.raw_tx.as_slice(),
            TxType::MiniAssert(assert_idx),
            None,
        )
        .await
        .context(format!(
            "failed to send mini assert transaction {assert_idx}"
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
    let all_txs_2 = operator0
        .internal_create_signed_txs(TransactionRequest {
            kickoff_id: Some(
                KickoffData {
                    operator_xonly_pk: op0_xonly_pk,
                    round_idx: RoundIndex::Round(1),
                    kickoff_idx: 0,
                }
                .into(),
            ),
            ..base_tx_req
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
        None,
    )
    .await
    .context("failed to send reimburse transaction")?;

    tracing::info!("Happy Path 2 test completed successfully");
    Ok(())
}

/// Simple Assert flow without watchtower challenges/acks
pub async fn run_simple_assert_flow(
    config: &mut BridgeConfig,
    rpc: ExtendedBitcoinRpc,
) -> Result<()> {
    tracing::info!("Starting Simple Assert Flow");

    let (actors, tx_senders, _deposit_info, _kickoff_idx, base_tx_req, all_txs, _op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Directly create and send assert transactions directly
    tracing::info!("Creating and sending assert transactions directly");

    // Get deposit data and kickoff ID for assert creation
    rpc.mine_blocks(8 * BLOCKS_PER_HOUR as u64).await?;
    // Create assert transactions for operator 0
    let mut operator0 = actors.get_operator_client_by_index(0);
    let assert_txs = operator0
        .internal_create_assert_commitment_txs(base_tx_req)
        .await?
        .into_inner();

    // Ensure all assert transactions are sent in order
    for tx in assert_txs.signed_txs.iter() {
        tracing::info!(
            "Sending assert transaction of type: {:?}",
            tx.transaction_type
        );
        send_tx(
            &tx_sender,
            &rpc,
            tx.raw_tx.as_slice(),
            tx.transaction_type.unwrap().try_into().unwrap(),
            None,
        )
        .await?;
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
pub async fn run_bad_path_1(config: &mut BridgeConfig, rpc: ExtendedBitcoinRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 1 test");

    let (actors, tx_senders, _dep_params, _kickoff_idx, base_tx_req, all_txs, _op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

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
    let mut verifier = actors.get_verifier_client_by_index(watchtower_idx);
    let watchtower_challenge_tx = verifier
        .internal_create_watchtower_challenge(base_tx_req.clone())
        .await?
        .into_inner();
    tracing::info!(
        "Sending watchtower challenge transaction for watchtower {}",
        watchtower_idx
    );
    let rbf_info: Option<RbfSigningInfo> = watchtower_challenge_tx
        .rbf_info
        .map(|rbf_rpc| rbf_rpc.try_into().unwrap());
    send_tx(
        &tx_sender,
        &rpc,
        watchtower_challenge_tx.raw_tx.as_slice(),
        TxType::WatchtowerChallenge(watchtower_idx),
        rbf_info,
    )
    .await
    .context(format!(
        "failed to send watchtower challenge transaction for watchtower {watchtower_idx}"
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
pub async fn run_bad_path_2(config: &mut BridgeConfig, rpc: ExtendedBitcoinRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 2 test");

    let (_actors, tx_senders, _dep_params, _kickoff_idx, _base_tx_req, all_txs, _op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

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
pub async fn run_bad_path_3(config: &mut BridgeConfig, rpc: ExtendedBitcoinRpc) -> Result<()> {
    tracing::info!("Starting Bad Path 3 test");

    let (actors, tx_senders, _deposit_info, _kickoff_idx, _base_tx_req, all_txs, _op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

    // Send Round Transaction
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Kickoff).await?;

    // Send Challenge Transaction
    tracing::info!("Sending challenge transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Challenge).await?;

    // Send Watchtower Challenge Transactions
    for watchtower_idx in 0..actors.get_num_verifiers() {
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
    for verifier_idx in 0..actors.get_num_verifiers() {
        tracing::info!(
            "Sending operator challenge ack transaction for watchtower {}",
            verifier_idx
        );
        send_tx_with_type(
            &rpc,
            &tx_sender,
            &all_txs,
            TxType::OperatorChallengeAck(verifier_idx),
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

// Operator successfully sends challenge timeout for one deposit, but doesn't
// spend its remaining kickoffs, state machine should automatically send any
// unspent kickoff connector tx to burn operators collateral
pub async fn run_unspent_kickoffs_with_state_machine(
    config: &mut BridgeConfig,
    rpc: ExtendedBitcoinRpc,
) -> Result<()> {
    let (_actors, tx_senders, _deposit_info, _kickoff_idx, _base_tx_req, all_txs, _op0_xonly_pk) =
        base_setup(config, &rpc).await?;

    let tx_sender = tx_senders[0].clone();

    // Send Round Transaction
    tracing::info!("Sending round transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::Round).await?;

    // state machine should burn the collateral after ready to reimburse tx gets sent
    let ready_to_reimburse_tx =
        get_tx_from_signed_txs_with_type(&all_txs, TxType::ReadyToReimburse)?;
    let collateral_utxo = OutPoint {
        txid: ready_to_reimburse_tx.compute_txid(),
        vout: 0,
    };

    // Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse transaction");
    send_tx_with_type(&rpc, &tx_sender, &all_txs, TxType::ReadyToReimburse).await?;

    let collateral_burn_txid = get_txid_where_utxo_is_spent(&rpc, collateral_utxo).await?;

    // calculate unspent kickoff tx txids and check if any of them is where collateral was spent
    let is_spent_by_unspent_kickoff_tx = (0..config.protocol_paramset().num_kickoffs_per_round)
        .map(|i| {
            let tx = get_tx_from_signed_txs_with_type(&all_txs, TxType::UnspentKickoff(i)).unwrap();
            tx.compute_txid()
        })
        .any(|txid| txid == collateral_burn_txid);

    assert!(is_spent_by_unspent_kickoff_tx);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_simple_assert_flow() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_simple_assert_flow(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    // #[ignore = "Design changes in progress"]
    async fn test_happy_path_1() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path_1(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_happy_path_2() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path_2(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_path_1() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_1(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bad_path_2() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_2(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "Disprove is not ready"]
    async fn test_bad_path_3() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_bad_path_3(&mut config, rpc).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_operator_end_round() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_operator_end_round(&mut config, rpc, false)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_operator_end_round_with_challenge() {
        let mut config = create_test_config_with_thread_name().await;
        config.test_params.should_run_state_manager = false;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_operator_end_round(&mut config, rpc, true)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_unspent_kickoffs_with_state_machine() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        run_unspent_kickoffs_with_state_machine(&mut config, rpc)
            .await
            .unwrap();
    }
}
