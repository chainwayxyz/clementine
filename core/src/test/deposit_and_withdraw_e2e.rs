use super::common::citrea::get_bridge_params;
use crate::actor::Actor;
use crate::bitvm_client::{self, SECP};
use crate::builder::address::create_taproot_address;
use crate::builder::script::SpendPath;
use crate::builder::transaction::input::{SpendableTxIn, UtxoVout};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::header_chain_prover::HeaderChainProver;
use crate::rpc::clementine::{
    Deposit, FeeType, FinalizedPayoutParams, KickoffId, NormalSignatureKind, RawSignedTx,
    SendTxRequest, TransactionRequest, WithdrawParams,
};
use crate::test::common::citrea::{MockCitreaClient, SECRET_KEYS};
use crate::test::common::tx_utils::{
    ensure_outpoint_spent, ensure_outpoint_spent_while_waiting_for_light_client_sync,
    ensure_tx_onchain, get_txid_where_utxo_is_spent,
};
use crate::test::common::tx_utils::{
    get_tx_from_signed_txs_with_type, wait_for_fee_payer_utxos_to_be_in_mempool,
};
use crate::test::common::{
    create_regtest_rpc, generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool,
    poll_get, poll_until_condition, run_multiple_deposits, run_single_deposit,
};
use crate::utils::initialize_logger;
use crate::UTXO;
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
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

#[derive(PartialEq)]
pub enum CitreaDepositAndWithdrawE2EVariant {
    GenesisHeightZero,
    GenesisHeightNonZero,
}

struct CitreaDepositAndWithdrawE2E {
    variant: CitreaDepositAndWithdrawE2EVariant,
}

#[async_trait]
impl TestCase for CitreaDepositAndWithdrawE2E {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-txindex=1",
                "-fallbackfee=0.000001",
                "-rpcallowip=0.0.0.0/0",
                "-dustrelayfee=0",
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

        let (sequencer, full_node, lc_prover, batch_prover, da) =
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

        rpc.mine_blocks(12).await.unwrap();

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .await
        .unwrap();

        if self.variant == CitreaDepositAndWithdrawE2EVariant::GenesisHeightNonZero {
            let genesis_height: u32 = 10;

            let genesis_chain_state_hash = HeaderChainProver::get_chain_state_from_height(
                rpc.clone(),
                genesis_height as u64,
                config.protocol_paramset().network,
            )
            .await
            .unwrap()
            .to_hash();

            let paramset = ProtocolParamset {
                genesis_height,
                genesis_chain_state_hash,
                ..ProtocolParamset::default()
            };

            config.protocol_paramset = Box::leak(Box::new(paramset));
        }

        let (mut actors, deposit_infos, move_txids, _deposit_blockhashs, verifiers_public_keys) =
            run_multiple_deposits::<CitreaClient>(&mut config, rpc.clone(), 2, None).await?;

        let citrea_e2e_data = citrea::CitreaE2EData {
            sequencer,
            full_node,
            lc_prover,
            batch_prover,
            da,
            config: config.clone(),
            citrea_client: &citrea_client,
            rpc: &rpc,
        };

        let mut withdrawal_index: u32 = 0;

        tracing::info!(
            "Deposit ending block_height: {:?}",
            rpc.client.get_block_count().await?
        );

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        let mut withdrawal_infos = Vec::new();

        for move_txid in move_txids.iter() {
            let (withdrawal_utxo, payout_txout, sig) =
                citrea::get_new_withdrawal_utxo_and_register_to_citrea(
                    *move_txid,
                    &citrea_e2e_data,
                )
                .await;
            withdrawal_infos.push((withdrawal_index, withdrawal_utxo, payout_txout, sig));
            withdrawal_index += 1;
        }

        let mut reimburse_connectors = Vec::new();

        // withdraw one with a kickoff
        for ((withdrawal_id, withdrawal_utxo, payout_txout, sig), deposit_info) in
            withdrawal_infos.iter().zip(deposit_infos.iter()).take(1)
        {
            // set up verifier 0 db
            let verifier_0_config = {
                let mut config = config.clone();
                config.db_name += "0";
                config
            };
            let op0_xonly_pk = verifiers_public_keys[0].x_only_public_key().0;
            let db = Database::new(&verifier_0_config)
                .await
                .expect("failed to create database");
            let operator0 = actors.get_operator_by_index(0);

            reimburse_connectors.push(
                citrea::withdraw_and_challenge(
                    operator0,
                    op0_xonly_pk,
                    &db,
                    *withdrawal_id,
                    withdrawal_utxo,
                    payout_txout,
                    sig,
                    &citrea_e2e_data,
                    deposit_info,
                )
                .await,
            );
        }

        for reimburse_connector in reimburse_connectors.iter() {
            // ensure all reimburse connectors are spent
            ensure_outpoint_spent_while_waiting_for_light_client_sync(
                &rpc,
                lc_prover,
                *reimburse_connector,
            )
            .await
            .unwrap();
        }
        // add a new verifier
        let new_sk = SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
        actors.add_verifier(new_sk).await.unwrap();

        let new_agg_key = actors.get_nofn_aggregated_xonly_pk().await.unwrap();
        citrea_client
            .update_nofn_aggregated_key(new_agg_key, config.protocol_paramset(), sequencer)
            .await
            .unwrap();

        Ok(())
    }
}

/// Tests the complete deposit and withdrawal flow between Bitcoin and Citrea networks.
///
/// # Arrange
/// * Sets up Citrea infrastructure (sequencer, prover, DA layer)
/// * Configures bridge parameters and connects to Bitcoin regtest
///
/// # Act
/// * Executes a deposit from Bitcoin to Citrea
/// * Waits for deposit finalization and batch proof generation
/// * Executes a withdrawal from Citrea back to Bitcoin
/// * Processes the payout transaction
///
/// # Assert
/// * Verifies balance is 0 before deposit and non-zero after deposit
/// * Confirms withdrawal fails without Citrea-side withdrawal
/// * Verifies payout transaction is successfully processed
/// * Confirms kickoff transaction is created and mined
/// * Verifies reimburse connector is spent (proper payout handling)
#[tokio::test]
#[ignore = "This test does the same thing as disprove_script_test_healthy"]
async fn citrea_deposit_and_withdraw_e2e() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let citrea_e2e = CitreaDepositAndWithdrawE2E {
        variant: CitreaDepositAndWithdrawE2EVariant::GenesisHeightZero,
    };
    TestCaseRunner::new(citrea_e2e).run().await
}

#[tokio::test]
#[ignore = "Run in standalone VM in CI"]
async fn citrea_deposit_and_withdraw_e2e_non_zero_genesis_height() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let citrea_e2e = CitreaDepositAndWithdrawE2E {
        variant: CitreaDepositAndWithdrawE2EVariant::GenesisHeightNonZero,
    };
    TestCaseRunner::new(citrea_e2e).run().await
}

/// Tests the deposit and withdrawal flow using a mocked Citrea client in a truthful scenario.
///
/// # Arrange
/// * Sets up mock Citrea client
/// * Configures bridge parameters
///
/// # Act
/// * Executes a deposit from Bitcoin to mock Citrea
/// * Registers the deposit in the mock client
/// * Executes a withdrawal from mock Citrea back to Bitcoin
/// * Processes the payout transaction
///
/// # Assert
/// * Verifies payout transaction is successfully created and mined
/// * Confirms payout is properly handled in database (added then removed from unhandled list)
/// * Verifies kickoff transaction is created and mined
/// * Confirms challenge output is spent via timeout (no challenge occurred)
/// * Verifies reimburse connector is spent (proper payout handling)
#[tokio::test]
async fn mock_citrea_run_truthful() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client = MockCitreaClient::new(
        config.citrea_rpc_url.clone(),
        "".to_string(),
        config.citrea_chain_id,
        None,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (actors, _deposit_params, move_txid, _deposit_blockhash, verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
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
    let (dust_utxo, payout_txout, sig) = generate_withdrawal_transaction_and_signature(
        &config,
        &rpc,
        &withdrawal_address,
        config.protocol_paramset().bridge_amount
            - config
                .operator_withdrawal_fee_sats
                .unwrap_or(Amount::from_sat(0)),
    )
    .await;

    let withdrawal_utxo = dust_utxo.outpoint;

    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

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
    let mut operator0 = actors.get_operator_by_index(0);

    let payout_txid = poll_get(
        async || {
            let withdrawal_response = operator0
                .withdraw(WithdrawParams {
                    withdrawal_id: 0,
                    input_signature: sig.serialize().to_vec(),
                    input_outpoint: Some(withdrawal_utxo.into()),
                    output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                    output_amount: payout_txout.value.to_sat(),
                })
                .await;

            match withdrawal_response {
                Ok(withdrawal_response) => {
                    tracing::info!("Withdrawal response: {:?}", withdrawal_response);
                    let payout_txid = Some(Txid::from_byte_array(
                        withdrawal_response
                            .into_inner()
                            .txid
                            .unwrap()
                            .txid
                            .try_into()
                            .unwrap(),
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
        vout: UtxoVout::ReimburseInKickoff.get_vout(),
    };

    let _kickoff_block_height =
        mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(300))
            .await
            .unwrap();

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    // wait until the light client prover is synced to the same height

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::Challenge.get_vout(),
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

/// Tests protocol challenge mechanism when a malicious action is detected.
///
/// # Arrange
/// * Sets up mock Citrea client
/// * Executes deposit and registers it in mock client
///
/// # Act
/// * Registers a withdrawal in mock Citrea
/// * Operator attempts malicious action by calling internal_finalized_payout
/// * Operator attempts a second malicious action with another kickoff transaction
///
/// # Assert
/// * Verifies first kickoff transaction is challenged (challenge output has correct amount)
/// * Confirms second kickoff transaction is not challenged (prevents double-challenge)
/// * Verifies challenge spent transaction has expected challenge amount for first attempt
/// * Confirms challenge spent transaction does not have challenge amount for second attempt
#[tokio::test]
async fn mock_citrea_run_truthful_opt_payout() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client = MockCitreaClient::new(
        config.citrea_rpc_url.clone(),
        "".to_string(),
        config.citrea_chain_id,
        None,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (actors, _deposit_params, move_txid, _deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
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
    let mut aggregator = actors.get_aggregator();
    // should give err before deposit is confirmed on citrea
    assert!(aggregator
        .optimistic_payout(WithdrawParams {
            withdrawal_id: 0,
            input_signature: sig.serialize().to_vec(),
            input_outpoint: Some(withdrawal_utxo.into()),
            output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
            output_amount: payout_txout.value.to_sat(),
        })
        .await
        .is_err());

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.client.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
        .await;
    rpc.mine_blocks(5).await.unwrap();

    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    tracing::info!("Collecting deposits and withdrawals");

    // mine 1 block to make sure the withdrawal is in the next block
    // rpc.mine_blocks(1).await.unwrap();

    let current_block_height = rpc.client.get_block_count().await.unwrap();

    // should give err before withdrawal is confirmed on citrea
    assert!(aggregator
        .optimistic_payout(WithdrawParams {
            withdrawal_id: 0,
            input_signature: sig.serialize().to_vec(),
            input_outpoint: Some(withdrawal_utxo.into()),
            output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
            output_amount: payout_txout.value.to_sat(),
        })
        .await
        .is_err());

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;
    // Mine some blocks so that block syncer counts it as finalzied
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    tracing::info!("Withdrawal tx sent");

    let opt_payout_tx = poll_get(
        async || {
            let payout_resp = aggregator
                .optimistic_payout(WithdrawParams {
                    withdrawal_id: 0,
                    input_signature: sig.serialize().to_vec(),
                    input_outpoint: Some(withdrawal_utxo.into()),
                    output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                    output_amount: payout_txout.value.to_sat(),
                })
                .await;

            match payout_resp {
                Ok(payout_response) => {
                    tracing::info!("Withdrawal response: {:?}", payout_response);
                    let opt_payout_tx: Transaction = payout_response.into_inner().try_into()?;
                    Ok(Some(opt_payout_tx))
                }
                Err(e) => {
                    tracing::warn!("Optimistic payout error: {:?}", e);
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

    tracing::info!("Optimistic payout tx: {:?}", opt_payout_tx);

    tracing::info!("Ensuring move txid bridge deposit is spent");
    ensure_outpoint_spent(
        &rpc,
        OutPoint {
            txid: move_txid,
            vout: (UtxoVout::DepositInMove).get_vout(),
        },
    )
    .await
    .unwrap();
    tracing::info!("Bridge deposit spent");
}

#[tokio::test]
async fn mock_citrea_run_malicious() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client = MockCitreaClient::new(
        config.citrea_rpc_url.clone(),
        "".to_string(),
        config.citrea_chain_id,
        None,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (actors, deposit_info, move_txid, _deposit_blockhash, _) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
            .await
            .unwrap();
    let db = Database::new(&BridgeConfig {
        db_name: config.db_name.clone() + "0",
        ..config.clone()
    })
    .await
    .expect("failed to create database");

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

    let mut operator0 = actors.get_operator_by_index(0);
    let kickoff_txid: bitcoin::Txid = operator0
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

    let _kickoff_block_height =
        mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(1800))
            .await
            .unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::Challenge.get_vout(),
    };

    let challenge_spent_txid = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint)
        .await
        .unwrap();

    tracing::info!("Challenge outpoint spent txid: {:?}", challenge_spent_txid);

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
    let kickoff_txid_2: bitcoin::Txid = operator0
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: vec![0u8; 32],
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
        })
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    wait_for_fee_payer_utxos_to_be_in_mempool(&rpc, db, kickoff_txid_2)
        .await
        .unwrap();
    rpc.mine_blocks(1).await.unwrap();
    let _kickoff_block_height2 =
        mine_once_after_in_mempool(&rpc, kickoff_txid_2, Some("Kickoff tx2"), Some(1800))
            .await
            .unwrap();

    tracing::info!(
        "Kickoff txid: {:?}, kickoff txid 2: {:?}",
        kickoff_txid,
        kickoff_txid_2
    );
    // second kickoff tx should not be challenged as a kickoff of the same round was already challenged
    let challenge_outpoint_2 = OutPoint {
        txid: kickoff_txid_2,
        vout: UtxoVout::Challenge.get_vout(),
    };
    let challenge_spent_txid_2 = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint_2)
        .await
        .unwrap();
    let tx_2 = rpc.get_tx_of_txid(&challenge_spent_txid_2).await.unwrap();
    // tx_2 should not have challenge amount output
    assert!(tx_2.output[0].value != config.protocol_paramset().operator_challenge_amount);

    // TODO: check that operators collateral got burned. It can't be checked right now as we dont have auto disprove implemented.
}

/// Tests protocol safety when an operator exits before a challenge can be made.
///
/// # Arrange
/// * Sets up mock Citrea client
/// * Executes deposit and registers it in mock client
///
/// # Act
/// * Registers a withdrawal in mock Citrea
/// * Operator burns collateral (exits protocol)
/// * Operator attempts malicious action by calling internal_finalized_payout after exit
///
/// # Assert
/// * Verifies kickoff transaction is created and mined
/// * Confirms challenge output is not spent on a challenge (operator already exited)
/// * Verifies challenge spent transaction does not have challenge amount
/// * Demonstrates protocol safety by preventing challenges after operator exit
#[tokio::test]
async fn mock_citrea_run_malicious_after_exit() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let mut citrea_client = MockCitreaClient::new(
        config.citrea_rpc_url.clone(),
        "".to_string(),
        config.citrea_chain_id,
        None,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.client.get_block_count().await.unwrap()
    );
    let (actors, deposit_info, move_txid, _deposit_blockhash, verifier_pks) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
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

    let mut operator0 = actors.get_operator_by_index(0);
    let first_round_txs = operator0
        .internal_create_signed_txs(TransactionRequest {
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
            kickoff_id: Some(KickoffId {
                round_idx: 1,
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
    // send first round tx
    let mut aggregator = actors.get_aggregator();
    aggregator
        .internal_send_tx(SendTxRequest {
            raw_tx: Some(RawSignedTx {
                raw_tx: bitcoin::consensus::serialize(&round_tx),
            }),
            fee_type: FeeType::Cpfp as i32,
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let round_txid = round_tx.compute_txid();
    ensure_tx_onchain(&rpc, round_txid).await.unwrap();
    tracing::warn!("Round tx sent");

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
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: round_tx.output[0].value - Amount::from_sat(1000),
            script_pubkey: round_tx.output[0].script_pubkey.clone(),
        }))
        .finalize();

    actor
        .tx_sign_and_fill_sigs(&mut spend_txhandler, &[], None)
        .unwrap();
    let spend_tx = spend_txhandler.promote().unwrap().get_cached_tx().clone();

    rpc.client.send_raw_transaction(&spend_tx).await.unwrap();

    // mine 1 block to make sure collateral burn tx lands onchain
    rpc.mine_blocks(1).await.unwrap();
    let deposit: Deposit = deposit_info.clone().into();

    // because operator collaterl was spent outside of the protocol, new deposit with this operator should be rejected
    assert!(aggregator.new_deposit(deposit).await.is_err());

    let kickoff_txid: bitcoin::Txid = operator0
        .internal_finalized_payout(FinalizedPayoutParams {
            payout_blockhash: vec![0u8; 32],
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
        })
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    let _kickoff_block_height =
        mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(1800))
            .await
            .unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::Challenge.get_vout(),
    };

    let challenge_spent_txid = get_txid_where_utxo_is_spent(&rpc, challenge_outpoint)
        .await
        .unwrap();

    // check that challenge utxo should not be spent on a challenge as operator exited the protocol
    let tx = rpc.get_tx_of_txid(&challenge_spent_txid).await.unwrap();

    assert!(tx.output[0].value != config.protocol_paramset().operator_challenge_amount);
}
