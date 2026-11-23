use crate::bitvm_client::SECP;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::rpc::clementine::{WithdrawParams, WithdrawParamsWithSig};
use crate::rpc::ecdsa_verification_sig::OperatorWithdrawalMessage;
use crate::test::common::citrea::MockCitreaClient;
use crate::test::common::test_actors::TestActors;
use crate::test::common::{
    create_actors, create_regtest_rpc, generate_withdrawal_transaction_and_signature, poll_get,
    poll_until_condition,
};
use crate::test::common::{create_test_config_with_thread_name, run_single_deposit};
use crate::test::sign::sign_withdrawal_verification_signature;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use eyre::Context;
use std::time::Duration;
use tonic::Request;

struct HandledPayout {
    deposit_outpoint: OutPoint,
    payout_txid: Txid,
    kickoff_txid: Txid,
}

/// Operators with no-automation get reimbursed through `get_reimbursement_txs`.
///
/// Covers two kickoffs reserved in the same round, a stale
/// `BurnUnusedKickoffConnectors` that spends a later reservation, and recovery
/// of that third kickoff onto the next round.
#[tokio::test]
async fn mock_citrea_run_truthful_manual_reimbursement() {
    let mut config = create_test_config_with_thread_name().await;
    // set min relay fee to zero so that we do not need to CPFP
    config.test_params.mine_0_fee_txs = true;
    // Three signed connectors in a round so A and B can stay reserved while C
    // is still assigned a round-0 connector that a previously signed burn will spend.
    let mut paramset = config.protocol_paramset().clone();
    paramset.num_signed_kickoffs = 3;
    config.protocol_paramset = Box::leak(Box::new(paramset));

    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client = MockCitreaClient::new(
        config.citrea_rpc_url.clone(),
        "".to_string(),
        config.citrea_chain_id,
        None,
        config.citrea_request_timeout,
    )
    .await
    .unwrap();

    let actors = create_actors::<MockCitreaClient>(&config).await;
    let (db, _) = actors.get_operator_db_and_xonly_pk_by_index(0).await;

    let payout_a = deposit_and_payout(&mut config, &actors, &rpc, &mut citrea_client, &db, 0).await;
    let payout_b = deposit_and_payout(&mut config, &actors, &rpc, &mut citrea_client, &db, 1).await;

    let (round_a, _) = db
        .get_kickoff_connector_for_kickoff_txid(None, payout_a.kickoff_txid)
        .await
        .unwrap();
    let (round_b, _) = db
        .get_kickoff_connector_for_kickoff_txid(None, payout_b.kickoff_txid)
        .await
        .unwrap();
    assert_eq!(
        round_a, round_b,
        "first two kickoffs should be reserved in the same round"
    );

    let stale_burn = drive_until_burn(&config, &actors, &rpc, payout_a.deposit_outpoint).await;

    let kickoff_b = wait_for_tx_type(
        &actors,
        &rpc,
        payout_b.deposit_outpoint,
        TransactionType::Kickoff,
    )
    .await;
    let b_connector = kickoff_b.input[0].previous_output;
    assert!(
        stale_burn
            .input
            .iter()
            .all(|input| input.previous_output != b_connector),
        "burn signed while B is reserved must not spend B's kickoff connector"
    );

    let payout_c = deposit_and_payout(&mut config, &actors, &rpc, &mut citrea_client, &db, 2).await;
    let (round_c, _) = db
        .get_kickoff_connector_for_kickoff_txid(None, payout_c.kickoff_txid)
        .await
        .unwrap();
    assert_eq!(
        round_c, round_a,
        "third kickoff should also start in the same round so the held burn can spend it"
    );

    let kickoff_c = wait_for_tx_type(
        &actors,
        &rpc,
        payout_c.deposit_outpoint,
        TransactionType::Kickoff,
    )
    .await;
    let c_connector = kickoff_c.input[0].previous_output;
    assert!(
        stale_burn
            .input
            .iter()
            .any(|input| input.previous_output == c_connector),
        "held burn must spend C's reserved connector so recovery is required"
    );
    let old_c_kickoff_txid = payout_c.kickoff_txid;

    broadcast_signed_tx(
        &config,
        &rpc,
        &actors,
        TransactionType::BurnUnusedKickoffConnectors,
        stale_burn,
        payout_a.deposit_outpoint,
    )
    .await;

    let payout_c = wait_for_kickoff_reassignment(
        &actors,
        &db,
        &payout_c,
        payout_a.deposit_outpoint,
        old_c_kickoff_txid,
    )
    .await;
    let (round_c_new, _) = db
        .get_kickoff_connector_for_kickoff_txid(None, payout_c.kickoff_txid)
        .await
        .unwrap();
    assert!(
        round_c_new.to_index() > round_a.to_index(),
        "recovered kickoff should move to a later round, got {round_c_new:?} vs {round_a:?}"
    );

    complete_reimbursements(&config, &actors, &rpc, &[&payout_a, &payout_b, &payout_c]).await;
}

async fn deposit_and_payout(
    config: &mut BridgeConfig,
    actors: &TestActors<MockCitreaClient>,
    rpc: &ExtendedBitcoinRpc,
    citrea_client: &mut MockCitreaClient,
    db: &Database,
    withdrawal_id: u32,
) -> HandledPayout {
    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );
    let (deposit_params, move_txid, _deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(config, rpc.clone(), None, actors, None)
            .await
            .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, move_txid)
        .await;
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.protocol_paramset().network,
    );
    let (dust_utxo, payout_txout, sig) = generate_withdrawal_transaction_and_signature(
        config,
        rpc,
        &withdrawal_address,
        config.protocol_paramset().bridge_amount
            - config
                .operator_withdrawal_fee_sats
                .unwrap_or(Amount::from_sat(0)),
    )
    .await;

    let withdrawal_utxo = dust_utxo.outpoint;

    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    let current_block_height = rpc.get_block_count().await.unwrap();

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;

    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    tracing::info!("Withdrawal tx sent");
    let mut operator0 = actors.get_operator_client_by_index(0);

    assert!(operator0
        .get_reimbursement_txs(Request::new(deposit_params.deposit_outpoint.into()))
        .await
        .is_err());

    let withdrawal_params = WithdrawParams {
        withdrawal_id,
        input_signature: sig.serialize().to_vec(),
        input_outpoint: Some(withdrawal_utxo.into()),
        output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
        output_amount: payout_txout.value.to_sat(),
    };

    let verification_signature = sign_withdrawal_verification_signature::<OperatorWithdrawalMessage>(
        config,
        withdrawal_params.clone(),
    );
    let verification_signature_str = verification_signature.to_string();

    let payout_tx = loop {
        let withdrawal_response = operator0
            .withdraw(WithdrawParamsWithSig {
                withdrawal: Some(withdrawal_params.clone()),
                verification_signature: Some(verification_signature_str.clone()),
            })
            .await;

        tracing::info!("Withdrawal response: {:?}", withdrawal_response);

        match withdrawal_response {
            Ok(tx) => {
                let tx: Transaction = tx.into_inner().try_into().unwrap();
                break tx;
            }
            Err(e) => tracing::info!("Withdrawal error: {:?}", e),
        };

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };

    let payout_txid = payout_tx.compute_txid();
    tracing::info!("Payout txid: {:?}", payout_txid);

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    tracing::info!("Waiting until payout is handled");
    poll_until_condition(
        async || {
            Ok(db
                .get_handled_payout_kickoff_txid(None, payout_txid)
                .await?
                .is_some())
        },
        Some(Duration::from_secs(5 * 60)),
        Some(Duration::from_millis(200)),
    )
    .await
    .wrap_err("Timed out while waiting for payout to be handled")
    .unwrap();

    let kickoff_txid = db
        .get_handled_payout_kickoff_txid(None, payout_txid)
        .await
        .unwrap()
        .expect("Payout must be handled");

    tracing::info!("Kickoff txid: {:?}", kickoff_txid);

    HandledPayout {
        deposit_outpoint: deposit_params.deposit_outpoint,
        payout_txid,
        kickoff_txid,
    }
}

async fn drive_until_burn(
    config: &BridgeConfig,
    actors: &TestActors<MockCitreaClient>,
    rpc: &ExtendedBitcoinRpc,
    deposit_outpoint: OutPoint,
) -> Transaction {
    poll_get(
        async || {
            match fetch_reimbursement_txs(actors, deposit_outpoint).await {
                Ok(txs) => {
                    for (tx_type, tx) in txs {
                        if tx_type == TransactionType::BurnUnusedKickoffConnectors {
                            tracing::warn!(
                                "Holding BurnUnusedKickoffConnectors to insert a later reservation"
                            );
                            return Ok(Some(tx));
                        }
                        broadcast_signed_tx(config, rpc, actors, tx_type, tx, deposit_outpoint)
                            .await;
                    }
                }
                Err(e) => {
                    tracing::info!("Manual reimbursement error while waiting for burn: {:?}", e)
                }
            }
            rpc.mine_blocks(1).await.unwrap();
            Ok(None)
        },
        Some(Duration::from_secs(5 * 60)),
        Some(Duration::from_millis(500)),
    )
    .await
    .wrap_err("Timed out waiting for BurnUnusedKickoffConnectors")
    .unwrap()
}

async fn wait_for_kickoff_reassignment(
    actors: &TestActors<MockCitreaClient>,
    db: &Database,
    payout: &HandledPayout,
    other_deposit_outpoint: OutPoint,
    old_kickoff_txid: Txid,
) -> HandledPayout {
    poll_until_condition(
        async || {
            let _ = fetch_reimbursement_txs(actors, payout.deposit_outpoint).await;
            let _ = fetch_reimbursement_txs(actors, other_deposit_outpoint).await;
            Ok(db
                .get_handled_payout_kickoff_txid(None, payout.payout_txid)
                .await?
                .is_some_and(|txid| txid != old_kickoff_txid))
        },
        Some(Duration::from_secs(5 * 60)),
        Some(Duration::from_millis(500)),
    )
    .await
    .wrap_err("Timed out while waiting for kickoff reassignment after conflicting burn")
    .unwrap();

    let kickoff_txid = db
        .get_handled_payout_kickoff_txid(None, payout.payout_txid)
        .await
        .unwrap()
        .expect("Reassigned kickoff must exist");
    tracing::info!(
        "Kickoff reassigned from {:?} to {:?}",
        old_kickoff_txid,
        kickoff_txid
    );

    HandledPayout {
        deposit_outpoint: payout.deposit_outpoint,
        payout_txid: payout.payout_txid,
        kickoff_txid,
    }
}

async fn complete_reimbursements(
    config: &BridgeConfig,
    actors: &TestActors<MockCitreaClient>,
    rpc: &ExtendedBitcoinRpc,
    payouts: &[&HandledPayout],
) {
    poll_until_condition(
        async || {
            if all_reimburse_connectors_spent(rpc, payouts).await {
                return Ok(true);
            }
            for payout in payouts {
                match fetch_reimbursement_txs(actors, payout.deposit_outpoint).await {
                    Ok(txs) => {
                        for (tx_type, tx) in txs {
                            broadcast_signed_tx(
                                config,
                                rpc,
                                actors,
                                tx_type,
                                tx,
                                payout.deposit_outpoint,
                            )
                            .await;
                        }
                    }
                    Err(e) => tracing::info!(
                        "Manual reimbursement error for {:?}: {:?}",
                        payout.deposit_outpoint,
                        e
                    ),
                }
            }
            rpc.mine_blocks(1).await.unwrap();
            Ok(all_reimburse_connectors_spent(rpc, payouts).await)
        },
        Some(Duration::from_secs(5 * 60)),
        Some(Duration::from_millis(500)),
    )
    .await
    .wrap_err("Timed out waiting for all reimburse connectors to be spent")
    .unwrap();
}

async fn all_reimburse_connectors_spent(
    rpc: &ExtendedBitcoinRpc,
    payouts: &[&HandledPayout],
) -> bool {
    for payout in payouts {
        let reimburse_connector = OutPoint {
            txid: payout.kickoff_txid,
            vout: UtxoVout::ReimburseInKickoff.get_vout(),
        };
        if !rpc.is_tx_on_chain(&payout.kickoff_txid).await.unwrap()
            || !rpc.is_utxo_spent(&reimburse_connector).await.unwrap()
        {
            return false;
        }
    }
    true
}

async fn wait_for_tx_type(
    actors: &TestActors<MockCitreaClient>,
    rpc: &ExtendedBitcoinRpc,
    deposit_outpoint: OutPoint,
    want: TransactionType,
) -> Transaction {
    poll_get(
        async || {
            match fetch_reimbursement_txs(actors, deposit_outpoint).await {
                Ok(txs) => {
                    if let Some((_, tx)) = txs.into_iter().find(|(tx_type, _)| *tx_type == want) {
                        return Ok(Some(tx));
                    }
                }
                Err(e) => tracing::info!(
                    "Manual reimbursement error while waiting for {want:?}: {:?}",
                    e
                ),
            }
            rpc.mine_blocks(1).await.unwrap();
            Ok(None)
        },
        Some(Duration::from_secs(5 * 60)),
        Some(Duration::from_millis(500)),
    )
    .await
    .wrap_err(format!(
        "Timed out waiting for {want:?} for deposit {deposit_outpoint:?}"
    ))
    .unwrap()
}

async fn fetch_reimbursement_txs(
    actors: &TestActors<MockCitreaClient>,
    deposit_outpoint: OutPoint,
) -> Result<Vec<(TransactionType, Transaction)>, tonic::Status> {
    let mut operator0 = actors.get_operator_client_by_index(0);
    let txs = operator0
        .get_reimbursement_txs(Request::new(deposit_outpoint.into()))
        .await?;
    Ok(txs.into_inner().try_into().unwrap())
}

async fn broadcast_signed_tx(
    config: &BridgeConfig,
    rpc: &ExtendedBitcoinRpc,
    actors: &TestActors<MockCitreaClient>,
    tx_type: TransactionType,
    tx: Transaction,
    deposit_outpoint: OutPoint,
) {
    tracing::warn!("Got tx: {:?}", tx_type);
    tracing::warn!("Transaction: {:?}", tx);

    if tx_type == TransactionType::Kickoff {
        let kickoff_connector = tx.input[0].previous_output;
        if rpc.is_tx_on_chain(&kickoff_connector.txid).await.unwrap()
            && rpc.is_utxo_spent(&kickoff_connector).await.unwrap()
        {
            tracing::warn!(
                "Skipping kickoff {:?} because its connector is already spent",
                tx.compute_txid()
            );
            return;
        }
    }

    if !rpc.is_tx_on_chain(&tx.compute_txid()).await.unwrap() {
        rpc.send_raw_transaction(&tx).await.unwrap();
    }

    rpc.mine_blocks(1).await.unwrap();
    if tx_type == TransactionType::Kickoff {
        rpc.mine_blocks(
            config
                .protocol_paramset()
                .operator_challenge_timeout_timelock as u64
                + config.protocol_paramset().finality_depth as u64
                + 2,
        )
        .await
        .unwrap();
    } else if tx_type == TransactionType::ReadyToReimburse {
        rpc.mine_blocks(
            config.protocol_paramset().operator_reimburse_timelock as u64
                + config.protocol_paramset().finality_depth as u64
                + 2,
        )
        .await
        .unwrap();
    } else if tx_type == TransactionType::BurnUnusedKickoffConnectors {
        let mut operator0 = actors.get_operator_client_by_index(0);
        assert!(operator0
            .get_reimbursement_txs(Request::new(deposit_outpoint.into()))
            .await
            .is_err());
        rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    } else if tx_type == TransactionType::ChallengeTimeout {
        rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    }
}
