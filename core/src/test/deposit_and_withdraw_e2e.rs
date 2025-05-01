use super::common::citrea::get_bridge_params;
use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::script::SpendPath;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
use crate::citrea::mock::MockCitreaClient;
use crate::citrea::{CitreaClient, CitreaClientT, SATS_TO_WEI_MULTIPLIER};
use crate::database::Database;
use crate::rpc::clementine::{
    FinalizedPayoutParams, KickoffId, NormalSignatureKind, TransactionRequest, WithdrawParams,
};
use crate::test::common::citrea::SECRET_KEYS;
use crate::test::common::tx_utils::{
    ensure_outpoint_spent, ensure_outpoint_spent_while_waiting_for_light_client_sync,
    get_txid_where_utxo_is_spent,
};
use crate::test::common::{
    create_regtest_rpc, generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool,
    poll_get, poll_until_condition, run_single_deposit,
};
use crate::test::full_flow::get_tx_from_signed_txs_with_type;
use crate::UTXO;
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::FixedBytes;
use alloy::primitives::U256;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, TxOut, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use eyre::Context;
use std::time::Duration;

struct CitreaDepositAndWithdrawE2E;
#[async_trait]
impl TestCase for CitreaDepositAndWithdrawE2E {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-txindex=1",
                "-fallbackfee=0.000001",
                "-rpcallowip=0.0.0.0/0",
            ],
            ..Default::default()
        }
    }

    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            docker: TestCaseDockerConfig {
                bitcoin: true,
                citrea: true,
            },
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            bridge_initialize_params: get_bridge_params(),
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 60,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        rpc.mine_blocks(5).await.unwrap();

        let block_count = da.get_block_count().await?;
        tracing::debug!("Block count before deposit: {:?}", block_count);

        tracing::debug!(
            "Deposit starting at block height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (
            _verifiers,
            mut operators,
            _aggregator,
            _cleanup,
            _deposit_params,
            move_txid,
            _deposit_blockhash,
            verifiers_public_keys,
        ) = run_single_deposit::<CitreaClient>(&mut config, rpc.clone(), None).await?;
        tracing::debug!(
            "Deposit ending block_height: {:?}",
            rpc.client.get_block_count().await?
        );

        // Wait for TXs to be on-chain (CPFP etc.).
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        // Send deposit to Citrea
        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc.client.get_block(&tx_info.blockhash.unwrap()).await?;
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height as u64;

        citrea::wait_until_lc_contract_updated(sequencer.client.http_client(), block_height)
            .await
            .unwrap();

        // Without a deposit, the balance should be 0.
        assert_eq!(
            citrea::eth_get_balance(
                sequencer.client.http_client().clone(),
                crate::EVMAddress([1; 20]),
            )
            .await
            .unwrap(),
            0
        );

        tracing::debug!("Depositing to Citrea...");
        citrea::deposit(
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().unwrap(),
            tx,
        )
        .await?;
        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        // After the deposit, the balance should be non-zero.
        assert_ne!(
            citrea::eth_get_balance(
                sequencer.client.http_client().clone(),
                crate::EVMAddress([1; 20]),
            )
            .await
            .unwrap(),
            0
        );

        tracing::debug!("Deposit operations are successful.");

        // Prepare withdrawal transaction.
        let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let withdrawal_address = Address::p2tr(
            &SECP,
            user_sk.x_only_public_key(&SECP).0,
            None,
            config.protocol_paramset().network,
        );
        let (withdrawal_utxo_with_txout, payout_txout, sig) =
            generate_withdrawal_transaction_and_signature(
                &config,
                &rpc,
                &withdrawal_address,
                config.protocol_paramset().bridge_amount
                    - config
                        .operator_withdrawal_fee_sats
                        .unwrap_or(Amount::from_sat(0)),
            )
            .await;
        let withdrawal_utxo = withdrawal_utxo_with_txout.outpoint;
        tracing::debug!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

        // Without a withdrawal in Citrea, operator can't withdraw.
        assert!(operators[0]
            .withdraw(WithdrawParams {
                withdrawal_id: 0,
                input_signature: sig.serialize().to_vec(),
                input_outpoint: Some(withdrawal_utxo.into()),
                output_script_pubkey: payout_txout.txout().script_pubkey.to_bytes(),
                output_amount: payout_txout.txout().value.to_sat(),
            })
            .await
            .is_err());

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .await
        .unwrap();

        let citrea_withdrawal_tx = citrea_client
            .contract
            .withdraw(
                FixedBytes::from(withdrawal_utxo.txid.to_raw_hash().to_byte_array()),
                FixedBytes::from(withdrawal_utxo.vout.to_be_bytes()),
            )
            .value(U256::from(
                config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
            ))
            .send()
            .await
            .unwrap();
        tracing::debug!("Withdrawal TX sent in Citrea");

        // 1. force sequencer to commit
        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        tracing::debug!("Publish batch request sent");

        let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
        println!("Citrea withdrawal tx receipt: {:?}", receipt);

        // 2. wait until 2 commitment txs (commit, reveal) seen from DA to ensure their reveal prefix nonce is found
        da.wait_mempool_len(2, None).await?;

        // 3. generate FINALITY_DEPTH da blocks
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        // 4. wait for batch prover to generate proof on the finalized height
        let finalized_height = da.get_finalized_height(None).await.unwrap();
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        lc_prover.wait_for_l1_height(finalized_height, None).await?;

        // 5. ensure 2 batch proof txs on DA (commit, reveal)
        da.wait_mempool_len(2, None).await?;

        // 6. generate FINALITY_DEPTH da blocks
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();

        tracing::info!("Finalized height: {:?}", finalized_height);
        lc_prover.wait_for_l1_height(finalized_height, None).await?;
        tracing::info!("Waited for L1 height {}", finalized_height);

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let payout_txid = loop {
            let withdrawal_response = operators[0]
                .withdraw(WithdrawParams {
                    withdrawal_id: 0,
                    input_signature: sig.serialize().to_vec(),
                    input_outpoint: Some(withdrawal_utxo.into()),
                    output_script_pubkey: payout_txout.txout().script_pubkey.to_bytes(),
                    output_amount: payout_txout.txout().value.to_sat(),
                })
                .await;

            tracing::info!("Withdrawal response: {:?}", withdrawal_response);

            match withdrawal_response {
                Ok(withdrawal_response) => {
                    tracing::info!("Withdrawal response: {:?}", withdrawal_response);
                    break Txid::from_byte_array(
                        withdrawal_response.into_inner().txid.try_into().unwrap(),
                    );
                }
                Err(e) => {
                    tracing::info!("Withdrawal error: {:?}", e);
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        };
        tracing::info!("Payout txid: {:?}", payout_txid);

        mine_once_after_in_mempool(&rpc, payout_txid, Some("Payout tx"), None).await?;

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

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
        while db
            .get_first_unhandled_payout_by_operator_xonly_pk(None, op0_xonly_pk)
            .await?
            .is_none()
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tracing::info!("Waiting until payout is handled");
        // wait until payout is handled
        while db
            .get_first_unhandled_payout_by_operator_xonly_pk(None, op0_xonly_pk)
            .await?
            .is_some()
        {
            tracing::info!("Payout is not handled yet");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let kickoff_txid = db
            .get_handled_payout_kickoff_txid(None, payout_txid)
            .await?
            .expect("Payout must be handled");

        let reimburse_connector = OutPoint {
            txid: kickoff_txid,
            vout: 2,
        };

        // wait 3 seconds so fee payer txs are sent to mempool
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // mine 1 block to make sure the fee payer txs are in the next block
        rpc.mine_blocks(1).await.unwrap();

        // Wait for the kickoff tx to be onchain
        let kickoff_block_height =
            mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(1800)).await?;

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        // wait until the light client prover is synced to the same height
        lc_prover
            .wait_for_l1_height(kickoff_block_height as u64, None)
            .await?;

        // Ensure the reimburse connector is spent
        ensure_outpoint_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            reimburse_connector,
        )
        .await
        .unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn citrea_deposit_and_withdraw_e2e() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:46096297b7663a2e4a105b93e57e6dd3215af91c",
    );
    TestCaseRunner::new(CitreaDepositAndWithdrawE2E).run().await
}

#[tokio::test]
async fn mock_citrea_run_truthful() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client =
        MockCitreaClient::new(config.citrea_rpc_url.clone(), "".to_string(), None)
            .await
            .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (
        _verifiers,
        mut operators,
        _aggregator,
        _cleanup,
        _deposit_params,
        move_txid,
        _deposit_blockhash,
        verifiers_public_keys,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None)
        .await
        .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    // rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // Send deposit to Citrea
    let tx = rpc
        .client
        .get_raw_transaction(&move_txid, None)
        .await
        .unwrap();
    let tx_info = rpc
        .client
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc
        .client
        .get_block(&tx_info.blockhash.unwrap())
        .await
        .unwrap();
    let _block_height = rpc
        .client
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.client.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
        .await;
    rpc.mine_blocks(5).await.unwrap();

    // rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
    //     .await
    //     .unwrap();

    // Make a withdrawal
    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.protocol_paramset().network,
    );
    let (
        UTXO {
            outpoint: withdrawal_utxo,
            ..
        },
        payout_txout,
        sig,
    ) = generate_withdrawal_transaction_and_signature(
        &config,
        &rpc,
        &withdrawal_address,
        config.protocol_paramset().bridge_amount
            - config
                .operator_withdrawal_fee_sats
                .unwrap_or(Amount::from_sat(0)),
    )
    .await;

    // let withdrawal_response = operators[0]
    //     .withdraw(WithdrawParams {
    //         withdrawal_id: 0,
    //         input_signature: sig.serialize().to_vec(),
    //         input_outpoint: Some(withdrawal_utxo.into()),
    //         output_script_pubkey: payout_txout.txout().script_pubkey.to_bytes(),
    //         output_amount: payout_txout.txout().value.to_sat(),
    //     })
    //     .await;

    // tracing::info!("Withdrawal response: {:?}", withdrawal_response);

    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    tracing::info!("Collecting deposits and withdrawals");

    // mine 1 block to make sure the withdrawal is in the next block
    // rpc.mine_blocks(1).await.unwrap();

    let current_block_height = rpc.client.get_block_count().await.unwrap();

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;
    // Mine some blocks so that block syncer counts it as finalzied
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    // rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
    //     .await
    //     .unwrap();

    tracing::info!("Withdrawal tx sent");

    let payout_txid = poll_get(
        async || {
            let withdrawal_response = operators[0]
                .withdraw(WithdrawParams {
                    withdrawal_id: 0,
                    input_signature: sig.serialize().to_vec(),
                    input_outpoint: Some(withdrawal_utxo.into()),
                    output_script_pubkey: payout_txout.txout().script_pubkey.to_bytes(),
                    output_amount: payout_txout.txout().value.to_sat(),
                })
                .await;

            match withdrawal_response {
                Ok(withdrawal_response) => {
                    tracing::info!("Withdrawal response: {:?}", withdrawal_response);
                    let payout_txid = Some(Txid::from_byte_array(
                        withdrawal_response.into_inner().txid.try_into().unwrap(),
                    ));
                    Ok(Some(payout_txid))
                }
                Err(e) => {
                    tracing::info!("Withdrawal error: {:?}", e);
                    Ok(None)
                }
            }
        },
        Some(std::time::Duration::from_secs(120)),
        Some(std::time::Duration::from_millis(1000)),
    )
    .await
    .wrap_err("Withdrawal took too long")
    .unwrap();

    tracing::info!("Payout txid: {:?}", payout_txid);

    let payout_txid = payout_txid.unwrap();

    mine_once_after_in_mempool(&rpc, payout_txid, Some("Payout tx"), None)
        .await
        .unwrap();

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
        vout: 2,
    };

    // wait 3 seconds so fee payer txs are sent to mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block to make sure the fee payer txs are in the next block
    rpc.mine_blocks(1).await.unwrap();

    // Wait for the kickoff tx to be onchain
    let _kickoff_block_height =
        mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(1800))
            .await
            .unwrap();

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    // wait until the light client prover is synced to the same height

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: 0,
    };

    tracing::warn!("Waiting for challenge");
    let challenge_spent_txid = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint)
        .await
        .unwrap();
    tracing::warn!("Challenge spent txid: {:?}", challenge_spent_txid);

    // check that challenge utxo was spent on timeout -> meaning challenge was not sent
    let tx = rpc.get_tx_of_txid(&challenge_spent_txid).await.unwrap();
    // tx shouldn't have challenge amount sats as output as challenge timeout should be sent
    assert!(tx.output[0].value != config.protocol_paramset().operator_challenge_amount);

    tracing::warn!("Ensuring reimburse connector is spent");
    // Ensure the reimburse connector is spent
    ensure_outpoint_spent(&rpc, reimburse_connector)
        .await
        .unwrap();
    tracing::warn!("Reimburse connector spent");
}

#[tokio::test]
async fn mock_citrea_run_malicious() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client =
        MockCitreaClient::new(config.citrea_rpc_url.clone(), "".to_string(), None)
            .await
            .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (
        _verifiers,
        mut operators,
        _aggregator,
        _cleanup,
        deposit_info,
        move_txid,
        _deposit_blockhash,
        _,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None)
        .await
        .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    // rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // Send deposit to Citrea
    let tx = rpc
        .client
        .get_raw_transaction(&move_txid, None)
        .await
        .unwrap();
    let tx_info = rpc
        .client
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc
        .client
        .get_block(&tx_info.blockhash.unwrap())
        .await
        .unwrap();
    let _block_height = rpc
        .client
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.client.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
        .await;
    rpc.mine_blocks(5).await.unwrap();

    // rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
    //     .await
    //     .unwrap();

    // Make a withdrawal
    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.protocol_paramset().network,
    );
    let (
        UTXO {
            outpoint: withdrawal_utxo,
            ..
        },
        _payout_txout,
        _sig,
    ) = generate_withdrawal_transaction_and_signature(
        &config,
        &rpc,
        &withdrawal_address,
        config.protocol_paramset().bridge_amount
            - config
                .operator_withdrawal_fee_sats
                .unwrap_or(Amount::from_sat(0)),
    )
    .await;

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;

    // Mine some blocks so that block syncer counts it as finalzied
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    let kickoff_txid: bitcoin::Txid = operators[0]
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: vec![0u8; 32],
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
        })
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    tracing::info!("Kickoff txid: {:?}", kickoff_txid);

    // wait 3 seconds so fee payer txs are sent to mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block to make sure the fee payer txs are in the next block
    rpc.mine_blocks(1).await.unwrap();

    // Wait for the kickoff tx to be onchain
    let _kickoff_block_height =
        mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(1800))
            .await
            .unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: 0,
    };

    let challenge_spent_txid = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint)
        .await
        .unwrap();

    // check that challenge utxo was not spent on timeout -> meaning challenge was sent
    let tx = rpc.get_tx_of_txid(&challenge_spent_txid).await.unwrap();

    // tx should have challenge amount output
    if tx.output.len() == 1
        && tx.output[0].value != config.protocol_paramset().operator_challenge_amount
    {
        panic!("Challenge amount output is not correct, likely challenge timed out.");
    }
    assert!(tx.output[0].value == config.protocol_paramset().operator_challenge_amount);
    // send second kickoff tx
    let kickoff_txid_2: bitcoin::Txid = operators[0]
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: vec![0u8; 32],
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
        })
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();
    // wait 3 seconds so fee payer txs are sent to mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block to make sure the fee payer txs are in the next block
    rpc.mine_blocks(1).await.unwrap();

    let _kickoff_block_height2 =
        mine_once_after_in_mempool(&rpc, kickoff_txid_2, Some("Kickoff tx2"), Some(1800))
            .await
            .unwrap();

    tracing::warn!(
        "Kickoff txid: {:?}, kickoff txid 2: {:?}",
        kickoff_txid,
        kickoff_txid_2
    );
    // second kickoff tx should not be challenged as a kickoff of the same round was already challenged
    let challenge_outpoint_2 = OutPoint {
        txid: kickoff_txid_2,
        vout: 0,
    };
    let challenge_spent_txid_2 = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint_2)
        .await
        .unwrap();
    let tx_2 = rpc.get_tx_of_txid(&challenge_spent_txid_2).await.unwrap();
    // tx_2 should not have challenge amount output
    assert!(tx_2.output[0].value != config.protocol_paramset().operator_challenge_amount);

    // TODO: check that operators collateral got burned. It cant be checked right now as we dont have auto disprove implemented.
}

#[tokio::test]
async fn mock_citrea_run_malicious_after_exit() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client =
        MockCitreaClient::new(config.citrea_rpc_url.clone(), "".to_string(), None)
            .await
            .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (
        _verifiers,
        mut operators,
        _aggregator,
        _cleanup,
        deposit_info,
        move_txid,
        _deposit_blockhash,
        verifier_pks,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None)
        .await
        .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );

    // Send deposit to Citrea
    let tx = rpc
        .client
        .get_raw_transaction(&move_txid, None)
        .await
        .unwrap();
    let tx_info = rpc
        .client
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc
        .client
        .get_block(&tx_info.blockhash.unwrap())
        .await
        .unwrap();
    let _block_height = rpc
        .client
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.client.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
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
    let (
        UTXO {
            outpoint: withdrawal_utxo,
            ..
        },
        _payout_txout,
        _sig,
    ) = generate_withdrawal_transaction_and_signature(
        &config,
        &rpc,
        &withdrawal_address,
        config.protocol_paramset().bridge_amount
            - config
                .operator_withdrawal_fee_sats
                .unwrap_or(Amount::from_sat(0)),
    )
    .await;

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;

    // Mine some blocks so that block syncer counts it as finalzied
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    // operator 0's signer
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let first_round_txs = operators[0]
        .internal_create_signed_txs(TransactionRequest {
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
            kickoff_id: Some(KickoffId {
                round_idx: 0,
                operator_xonly_pk: verifier_pks[0].x_only_public_key().0.serialize().to_vec(),
                kickoff_idx: 0,
            }),
        })
        .await
        .unwrap()
        .into_inner();

    // get first round's tx
    let round_tx =
        get_tx_from_signed_txs_with_type(&first_round_txs, TransactionType::Round).unwrap();
    let round_txid = round_tx.compute_txid();

    let op_xonly_pk = actor.xonly_public_key;
    let (_op_address, op_spend) =
        create_taproot_address(&[], Some(op_xonly_pk), config.protocol_paramset().network);

    let mut spend_txhandler = TxHandlerBuilder::new(TransactionType::Dummy)
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            SpendableTxIn::new(
                OutPoint {
                    txid: round_txid,
                    vout: 0,
                },
                TxOut {
                    value: round_tx.output[0].value,
                    script_pubkey: round_tx.output[0].script_pubkey.clone(),
                },
                vec![],
                Some(op_spend),
            ),
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_burn_output()
        .finalize();

    actor
        .tx_sign_and_fill_sigs(&mut spend_txhandler, &[], None)
        .unwrap();
    let spend_tx = spend_txhandler.promote().unwrap().get_cached_tx().clone();

    rpc.client.send_raw_transaction(&spend_tx).await.unwrap();

    // mine 1 block to make sure collateral burn tx lands onchain
    rpc.mine_blocks(1).await.unwrap();

    tracing::warn!("here");

    let kickoff_txid: bitcoin::Txid = operators[0]
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: vec![0u8; 32],
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
        })
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    // wait 3 seconds so fee payer txs are sent to mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block to make sure the fee payer txs are in the next block
    rpc.mine_blocks(1).await.unwrap();

    // Wait for the kickoff tx to be onchain
    let _kickoff_block_height =
        mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(1800))
            .await
            .unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: 0,
    };

    let challenge_spent_txid = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint)
        .await
        .unwrap();

    // check that challenge utxo should not be spent on a challenge as operator exited the protocol
    let tx = rpc.get_tx_of_txid(&challenge_spent_txid).await.unwrap();

    assert!(tx.output[0].value != config.protocol_paramset().operator_challenge_amount);
}
