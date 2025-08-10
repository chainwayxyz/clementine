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
    create_regtest_rpc, generate_withdrawal_transaction_and_signature, poll_until_condition,
};
use crate::test::common::{create_test_config_with_thread_name, run_single_deposit};
use crate::test::sign::sign_withdrawal_verification_signature;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, OutPoint, Transaction};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use eyre::Context;
use std::time::Duration;
use tonic::Request;

// This test tests if operators with no-automation can get reimbursed using get_reimbursement_txs rpc endpoint.
#[tokio::test]
async fn mock_citrea_run_truthful_manual_reimbursement() {
    let mut config = create_test_config_with_thread_name().await;
    // set min relay fee to zero so that we do not need to CPFP
    config.test_params.mine_0_fee_txs = true;
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

    // do 2 deposits and get reimbursements
    let actors =
        deposit_and_get_reimbursement(&mut config, None, &rpc, &mut citrea_client, 0).await;
    let _actors =
        deposit_and_get_reimbursement(&mut config, Some(actors), &rpc, &mut citrea_client, 1).await;
}

async fn deposit_and_get_reimbursement(
    config: &mut BridgeConfig,
    actors: Option<TestActors<MockCitreaClient>>,
    rpc: &ExtendedBitcoinRpc,
    citrea_client: &mut MockCitreaClient,
    withdrawal_id: u32,
) -> TestActors<MockCitreaClient> {
    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );
    let (actors, deposit_params, move_txid, _deposit_blockhash, verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(config, rpc.clone(), None, actors, None)
            .await
            .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );

    // Send deposit to Citrea
    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, move_txid)
        .await;
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    // Make a withdrawal
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
    // Mine some blocks so that block syncer counts it as finalized

    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    tracing::info!("Withdrawal tx sent");
    let mut operator0 = actors.get_operator_client_by_index(0);

    // try to get reimbursement txs without a withdrawal, should return error
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

    // Setup tx_sender for sending transactions
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    let op0_xonly_pk = verifiers_public_keys[0].x_only_public_key().0;

    let db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");

    // wait until payout part is not null
    poll_until_condition(
        async || {
            Ok(db
                .get_first_unhandled_payout_by_operator_xonly_pk(None, op0_xonly_pk)
                .await?
                .is_some())
        },
        Some(Duration::from_secs(20 * 60)),
        Some(Duration::from_millis(200)),
    )
    .await
    .wrap_err("Timed out while waiting for payout to be added to unhandled list")
    .unwrap();

    tracing::info!("Waiting until payout is handled");
    // wait until payout is handled
    poll_until_condition(
        async || {
            Ok(db
                .get_first_unhandled_payout_by_operator_xonly_pk(None, op0_xonly_pk)
                .await?
                .is_none())
        },
        Some(Duration::from_secs(20 * 60)),
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

    let reimburse_connector = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::ReimburseInKickoff.get_vout(),
    };

    let mut cur_iteration = 0;
    // loop until reimburse connecter is spent
    while cur_iteration < 300
        && (!rpc.is_tx_on_chain(&kickoff_txid).await.unwrap()
            || !rpc.is_utxo_spent(&reimburse_connector).await.unwrap())
    {
        let manual_reimburse = operator0
            .get_reimbursement_txs(Request::new(deposit_params.deposit_outpoint.into()))
            .await;

        match manual_reimburse {
            Ok(txs) => {
                let txs: Vec<(TransactionType, Transaction)> = txs.into_inner().try_into().unwrap();
                for (tx_type, tx) in txs {
                    tracing::warn!("Got tx: {:?}", tx_type);
                    tracing::warn!("Transaction: {:?}", tx);
                    rpc.send_raw_transaction(&tx).await.unwrap();
                    // mine the tx
                    rpc.mine_blocks(1).await.unwrap();
                    if tx_type == TransactionType::Kickoff {
                        rpc.mine_blocks(
                            config
                                .protocol_paramset()
                                .operator_challenge_timeout_timelock
                                as u64
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
                        // the rpc endpoint should give an error because the BurnUnusedKickoffConnectors is not finalized yet
                        assert!(operator0
                            .get_reimbursement_txs(Request::new(
                                deposit_params.deposit_outpoint.into()
                            ))
                            .await
                            .is_err());
                        // mine blocks so that burn unused kickoff connectors is considered finalized
                        rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
                            .await
                            .unwrap();
                        // wait a bit for btc syncer to sync
                        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
                    } else if tx_type == TransactionType::ChallengeTimeout {
                        // mine blocks so that challenge timeout is considered finalized
                        rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
                            .await
                            .unwrap();
                        // wait a bit for btc syncer to sync
                        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
                    }
                }
            }
            Err(e) => tracing::info!("Manual reimbursement error: {:?}", e),
        }
        rpc.mine_blocks(1).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        cur_iteration += 1;
    }

    assert!(rpc.is_utxo_spent(&reimburse_connector).await.unwrap());

    actors
}
