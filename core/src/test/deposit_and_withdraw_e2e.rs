use super::common::citrea::get_bridge_params;
use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::script::SpendPath;
use crate::builder::transaction::input::{SpendableTxIn, UtxoVout};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::config::protocol::{ProtocolParamset, TESTNET4_TEST_PARAMSET};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{BaseDepositData, DepositInfo, DepositType};
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::header_chain_prover::HeaderChainProver;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::{
    Deposit, Empty, FeeType, FinalizedPayoutParams, KickoffId, NormalSignatureKind,
    OptimisticWithdrawParams, RawSignedTx, SendMoveTxRequest, SendTxRequest, TransactionRequest,
    WithdrawParams, WithdrawParamsWithSig,
};
use crate::rpc::ecdsa_verification_sig::{OperatorWithdrawalMessage, OptimisticPayoutMessage};
use crate::test::common::citrea::{
    get_new_withdrawal_utxo_and_register_to_citrea, register_replacement_deposit_to_citrea,
    start_citrea, update_config_with_citrea_e2e_values, CitreaE2EData, MockCitreaClient,
    SECRET_KEYS,
};
use crate::test::common::clementine_utils::{
    payout_and_start_kickoff, reimburse_with_optimistic_payout,
};
use crate::test::common::tx_utils::{
    ensure_outpoint_spent, ensure_outpoint_spent_while_waiting_for_state_mngr_sync,
    ensure_tx_onchain, get_tx_from_signed_txs_with_type, get_txid_where_utxo_is_spent,
    wait_for_fee_payer_utxos_to_be_in_mempool,
};
use crate::test::common::{
    create_actors, create_regtest_rpc, generate_withdrawal_transaction_and_signature,
    get_deposit_address, mine_once_after_in_mempool, poll_get, poll_until_condition,
    run_single_deposit,
};
use crate::test::common::{
    create_test_config_with_thread_name, run_multiple_deposits, run_single_replacement_deposit,
};
use crate::test::sign::sign_withdrawal_verification_signature;
use crate::utils::initialize_logger;
use crate::{EVMAddress, UTXO};
use async_trait::async_trait;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
};
use eyre::Context;
use futures::future::try_join_all;
use secrecy::SecretString;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::Channel;
use tonic::Request;

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

    async fn run_test(&mut self, f: &mut TestFramework) -> citrea_e2e::Result<()> {
        tracing::info!("Starting Citrea");

        let (sequencer, full_node, lc_prover, batch_prover, da) =
            start_citrea(Self::sequencer_config(), f).await.unwrap();

        let mut config = create_test_config_with_thread_name().await;

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await?;

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
            config.citrea_request_timeout,
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

        // do 2 deposits
        let (mut actors, _deposit_infos, move_txids, _deposit_blockhashs, _) =
            run_multiple_deposits::<CitreaClient>(&mut config, rpc.clone(), 2, None).await?;

        let citrea_e2e_data = CitreaE2EData {
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
            rpc.get_block_count().await?
        );

        let mut withdrawal_infos = Vec::new();

        tracing::info!("Mining withdrawal utxos");
        for move_txid in move_txids.iter() {
            let (withdrawal_utxo, payout_txout, sig) =
                get_new_withdrawal_utxo_and_register_to_citrea(
                    *move_txid,
                    &citrea_e2e_data,
                    &actors,
                )
                .await;
            withdrawal_infos.push((withdrawal_index, withdrawal_utxo, payout_txout, sig));
            withdrawal_index += 1;
        }

        tracing::info!("Mining withdrawal utxos done");

        let mut reimburse_connectors = Vec::new();

        // withdraw one with a kickoff with operator 0
        let (op0_db, op0_xonly_pk) = actors.get_operator_db_and_xonly_pk_by_index(0).await;

        tracing::info!("Paying and challenging withdrawal 0");
        reimburse_connectors.push(
            payout_and_start_kickoff(
                actors.get_operator_client_by_index(0),
                op0_xonly_pk,
                &op0_db,
                withdrawal_infos[0].0,
                &withdrawal_infos[0].1,
                &withdrawal_infos[0].2,
                &withdrawal_infos[0].3,
                &citrea_e2e_data,
                &actors,
            )
            .await,
        );

        tracing::info!("Adding new verifier and operator");
        // add a new verifier
        let new_sk = SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
        actors.add_verifier(new_sk).await.unwrap();
        // add a new operator too that uses the new verifier
        let new_op_sk = SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
        let new_verifier_index = actors.num_total_verifiers - 1;
        actors
            .add_operator(new_op_sk, new_verifier_index)
            .await
            .unwrap();

        let new_agg_key = actors.get_nofn_aggregated_xonly_pk().unwrap();
        citrea_client
            .update_nofn_aggregated_key(new_agg_key, config.protocol_paramset(), sequencer)
            .await
            .unwrap();

        // do 3 more deposits
        tracing::info!("Running 3 more deposits");
        let (
            mut actors,
            _new_deposit_infos,
            new_move_txids,
            _deposit_blockhashs,
            _verifiers_public_keys,
        ) = run_multiple_deposits::<CitreaClient>(&mut config, rpc.clone(), 3, Some(actors))
            .await?;

        tracing::info!("3 more deposits done, doing 3 more withdrawals");
        // do 3 more withdrawals
        for move_txid in new_move_txids.iter() {
            let (withdrawal_utxo, payout_txout, sig) =
                get_new_withdrawal_utxo_and_register_to_citrea(
                    *move_txid,
                    &citrea_e2e_data,
                    &actors,
                )
                .await;
            withdrawal_infos.push((withdrawal_index, withdrawal_utxo, payout_txout, sig));
            withdrawal_index += 1;
        }

        // do 1 kickoff with one of the new deposits using the new operator
        let new_operator_index = actors.num_total_operators - 1;
        let (new_operator_db, new_operator_xonly_pk) = actors
            .get_operator_db_and_xonly_pk_by_index(new_operator_index)
            .await;

        reimburse_connectors.push(
            payout_and_start_kickoff(
                actors.get_operator_client_by_index(new_operator_index),
                new_operator_xonly_pk,
                &new_operator_db,
                withdrawal_infos[2].0,
                &withdrawal_infos[2].1,
                &withdrawal_infos[2].2,
                &withdrawal_infos[2].3,
                &citrea_e2e_data,
                &actors,
            )
            .await,
        );

        // do 2 optimistic payouts, 1 with old 1 with new deposit, they should both work as all verifiers that
        // signed them still exist
        tracing::info!("Doing optimistic payout with old deposit");
        reimburse_with_optimistic_payout(
            &actors,
            withdrawal_infos[1].0,
            &withdrawal_infos[1].1,
            &withdrawal_infos[1].2,
            &withdrawal_infos[1].3,
            &citrea_e2e_data,
            move_txids[1],
        )
        .await
        .unwrap();

        tracing::info!("Doing optimistic payout with new deposit");
        reimburse_with_optimistic_payout(
            &actors,
            withdrawal_infos[3].0,
            &withdrawal_infos[3].1,
            &withdrawal_infos[3].2,
            &withdrawal_infos[3].3,
            &citrea_e2e_data,
            new_move_txids[1],
        )
        .await
        .unwrap();

        // save old nofn, then remove verifier 2
        let old_nofn_xonly_pk = actors.get_nofn_aggregated_xonly_pk().unwrap();
        tracing::info!("Removing verifier 2");
        actors.remove_verifier(2).await.unwrap();

        // update nofn on citrea
        let new_agg_key = actors.get_nofn_aggregated_xonly_pk().unwrap();
        citrea_client
            .update_nofn_aggregated_key(new_agg_key, config.protocol_paramset(), sequencer)
            .await
            .unwrap();

        // try an optimistic payout, should fail because a verifier that signed the withdrawal was removed
        tracing::info!("Trying optimistic payout with removed verifier, should fail");
        let _ = reimburse_with_optimistic_payout(
            &actors,
            withdrawal_infos[4].0,
            &withdrawal_infos[4].1,
            &withdrawal_infos[4].2,
            &withdrawal_infos[4].3,
            &citrea_e2e_data,
            new_move_txids[2],
        )
        .await
        .unwrap_err();

        // replace the deposit
        tracing::info!("Replacing deposit");
        let (
            mut actors,
            _replacement_deposit_info,
            replacement_move_txid,
            _replacement_deposit_blockhash,
        ) = run_single_replacement_deposit(
            &mut config,
            &rpc,
            new_move_txids[2],
            actors,
            old_nofn_xonly_pk,
        )
        .await
        .unwrap();

        tracing::info!("Registering replacement deposit to Citrea");
        register_replacement_deposit_to_citrea(
            &citrea_e2e_data,
            replacement_move_txid,
            withdrawal_infos[4].0,
            &actors,
        )
        .await
        .unwrap();

        // do optimistic payout with new replacement deposit, should work now
        // mine blocks until the replacement deposit is processed in handle_finalized_block
        loop {
            tracing::info!(
                "Trying to reimburse with optimistic payout for the replacement deposit"
            );
            let res = reimburse_with_optimistic_payout(
                &actors,
                withdrawal_infos[4].0,
                &withdrawal_infos[4].1,
                &withdrawal_infos[4].2,
                &withdrawal_infos[4].3,
                &citrea_e2e_data,
                replacement_move_txid,
            )
            .await;
            if res.is_ok() {
                break;
            }
            rpc.mine_blocks_while_synced(1, &actors).await.unwrap();
        }

        // wait for all past kickoff reimburse connectors to be spent
        tracing::info!("Waiting for all past kickoff reimburse connectors to be spent");
        for reimburse_connector in reimburse_connectors.iter() {
            ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
                &rpc,
                *reimburse_connector,
                &actors,
            )
            .await
            .unwrap();
        }

        // remove an operator and try a deposit, it should fail because the  operator is still in verifiers DB.
        // to make it not fail, operator data needs to be removed from verifiers DB.
        // if the behavior is changed in the future, the test should be updated.
        tracing::info!("Removing operator 1");
        actors.remove_operator(1).await.unwrap();
        // try to do a deposit, it should fail.
        assert!(run_single_deposit::<CitreaClient>(
            &mut config,
            rpc.clone(),
            None,
            Some(actors),
            None
        )
        .await
        .is_err());

        Ok(())
    }
}

/// Tests the complete deposit and withdrawal flow between Bitcoin and Citrea networks.
///
/// # Arrange
/// * Sets up Citrea infrastructure (sequencer, prover, DA layer)
/// * Configures bridge parameters and connects to Bitcoin regtest
/// * At first there are 2 operators; 0 and 1, and 4 verifiers; 0, 1, 2, 3
///
/// # Act
/// * Executes 2 deposits 0 and 1 from Bitcoin to Citrea
/// * Creates 2 withdrawal utxos and registers them to Citrea, no payout performerd yet
/// * Operator 0 pays and starts the kickoff for deposit 0
/// * New verifier 4 and new operator 2 that uses verifier 4 are added
/// * 3 new deposits are performed; 2, 3, 4
/// * Operator 2 pays and starts the kickoff for deposit 2
/// * Optimistic payout for deposit 1 is performed
/// * Optimistic payout for deposit 3 is performed
/// * Verifier 2 leaves the verifier set
/// * Optimistic payout for deposit 4 is attempted but fails because verifier 2 is not in signer set anymore,
/// but it is one of the nofn in deposit 4
/// * A replacement deposit is performed for deposit 4
/// * Optimistic payout for deposit 4 is performed with the new replacement deposit
/// * Remove operator 1, try to do a deposit, it should fail because the operator is still in verifiers DB.
/// * A check to see if reimburse connectors for the kickoffs created previously (for deposit 0 and 2) are spent,
///     meaning operators 0 and 2 got their funds back (the kickoff process is independent of actor set changes, they should
///     always work if the collected signatures are correct from start)
/// * Removes one operator and tries to do a deposit, it should fail because the operator is still in verifiers DB.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "Run in standalone VM in CI"]
async fn citrea_deposit_and_withdraw_e2e_non_zero_genesis_height() -> citrea_e2e::Result<()> {
    initialize_logger(None).expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let citrea_e2e = CitreaDepositAndWithdrawE2E {
        variant: CitreaDepositAndWithdrawE2EVariant::GenesisHeightNonZero,
    };
    TestCaseRunner::new(citrea_e2e).run().await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "Ignored, currently no specific reason to test with genesis height zero"]
async fn citrea_deposit_and_withdraw_e2e() -> citrea_e2e::Result<()> {
    initialize_logger(None).expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let citrea_e2e = CitreaDepositAndWithdrawE2E {
        variant: CitreaDepositAndWithdrawE2EVariant::GenesisHeightZero,
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
        config.citrea_request_timeout,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );
    let (actors, _deposit_params, move_txid, _deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
            .await
            .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );

    // Send deposit to Citrea
    let tx = rpc.get_raw_transaction(&move_txid, None).await.unwrap();
    let tx_info = rpc
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc.get_block(&tx_info.blockhash.unwrap()).await.unwrap();
    let _block_height = rpc
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.get_block_count().await.unwrap();
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

    let current_block_height = rpc.get_block_count().await.unwrap();

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;
    // Mine some blocks so that block syncer counts it as finalized
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    // rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
    //     .await
    //     .unwrap();

    tracing::info!("Withdrawal tx sent");
    let mut operator0 = actors.get_operator_client_by_index(0);

    let withdrawal_params = WithdrawParams {
        withdrawal_id: 0,
        input_signature: sig.serialize().to_vec(),
        input_outpoint: Some(withdrawal_utxo.into()),
        output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
        output_amount: payout_txout.value.to_sat(),
    };
    let verification_signature = sign_withdrawal_verification_signature::<OperatorWithdrawalMessage>(
        &config,
        withdrawal_params.clone(),
    );

    let verification_signature_str = verification_signature.to_string();

    loop {
        let withdrawal_response = operator0
            .withdraw(WithdrawParamsWithSig {
                withdrawal: Some(withdrawal_params.clone()),
                verification_signature: Some(verification_signature_str.clone()),
            })
            .await;

        tracing::info!("Withdrawal response: {:?}", withdrawal_response);

        match withdrawal_response {
            Ok(_) => break,
            Err(e) => tracing::info!("Withdrawal error: {:?}", e),
        };

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let payout_txid = get_txid_where_utxo_is_spent(&rpc, withdrawal_utxo)
        .await
        .unwrap();
    tracing::info!("Payout txid: {:?}", payout_txid);

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    // Setup tx_sender for sending transactions
    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    let db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");

    tracing::info!("Waiting until payout is handled");
    // wait until payout is handled
    poll_until_condition(
        async || {
            Ok(db
                .get_handled_payout_kickoff_txid(None, payout_txid)
                .await?
                .is_some())
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

// This test needs MEMPOOL_SPACE_API_KEY to be set to send nonstandard transactions to testnet4
#[tokio::test]
#[ignore = "This is a testnet4 test. It needs to be run alongside a local testnet4 node with some btc in its wallet"]
async fn testnet4_mock_citrea_run_truthful() {
    let mut config = create_test_config_with_thread_name().await;
    config.bitcoin_rpc_url = "http://localhost:48443".to_string();
    config.bitcoin_rpc_user = SecretString::from("admin".to_string());
    config.bitcoin_rpc_password = SecretString::from("admin".to_string());

    config.protocol_paramset = &TESTNET4_TEST_PARAMSET;

    config.test_params.all_operators_secret_keys =
        vec![SecretKey::from_slice(&[12u8; 32]).unwrap()];

    // use previous collateral funding outpoint on testnet4 so that we don't need to fund it again
    config.operator_collateral_funding_outpoint = Some(OutPoint {
        txid: Txid::from_str("a054cad4f2427f6659d87c11f781930cbdee74535267ebd848c628df2e3e5700")
            .unwrap(),
        vout: 0,
    });

    let rpc = ExtendedBitcoinRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
        None,
    )
    .await
    .unwrap();

    let mut citrea_client = MockCitreaClient::new(
        config.citrea_rpc_url.clone(),
        "".to_string(),
        config.citrea_chain_id,
        None,
        config.citrea_request_timeout,
    )
    .await
    .unwrap();

    // use previous withdrawal utxo so that we don't need to create a new one (if payout was already sent before,
    // otherwise you need to create a new one)
    let withdrawal_utxo = OutPoint {
        txid: Txid::from_str("3edf392111b78fc8a90f998ec7553bd2a2afc960473a2d27c83fd8d9db8c2a68")
            .unwrap(),
        vout: 1,
    };

    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    citrea_client
        .insert_withdrawal_utxo(
            config.protocol_paramset().start_height as u64,
            withdrawal_utxo,
        )
        .await;

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );

    // use previous move txid and register it to mock citrea  (if a deposit was done before)
    let move_txid =
        Txid::from_str("0176f77ab0c0a25703fc42c59e317594c6d2a2b711c680342166a9eaa02d51f1").unwrap();

    citrea_client
        .insert_deposit_move_txid(config.protocol_paramset().start_height as u64, move_txid)
        .await;

    let (actors, _deposit_infos, _move_txid, _deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(
            &mut config,
            rpc.clone(),
            None,
            None,
            Some(OutPoint {
                // use previous deposit outpoint so that we don't need to create a new one
                txid: Txid::from_str(
                    "93b3527dfcfe957c64a3210c04f19aaf9bfa8f5d8dd55c3e6f0613e631b8b135",
                )
                .unwrap(),
                vout: 1,
            }),
        )
        .await
        .unwrap();

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );

    // // Make a withdrawal
    // let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    // let withdrawal_address = Address::p2tr(
    //     &SECP,
    //     user_sk.x_only_public_key(&SECP).0,
    //     None,
    //     config.protocol_paramset().network,
    // );
    // let (
    //     UTXO {
    //         outpoint: withdrawal_utxo,
    //         ..
    //     },
    //     payout_txout,
    //     sig,
    // ) = generate_withdrawal_transaction_and_signature(
    //     &config,
    //     &rpc,
    //     &withdrawal_address,
    //     config.protocol_paramset().bridge_amount
    //         - config
    //             .operator_withdrawal_fee_sats
    //             .unwrap_or(Amount::from_sat(0)),
    // )
    // .await;

    // tracing::info!("Withdrawal tx sent, withdrawal utxo: {:?}", withdrawal_utxo);

    // // insert withdrawal utxo into next block for mock citrea
    // citrea_client
    //     .insert_withdrawal_utxo(
    //         (rpc.get_current_chain_height().await.unwrap() - TESTNET4_TEST_PARAMSET.finality_depth
    //             + 1) as u64,
    //         withdrawal_utxo,
    //     )
    //     .await;

    // loop {
    //     let withdrawal_response = _operators[0]
    //         .withdraw(WithdrawParams {
    //             withdrawal_id: 0,
    //             input_signature: sig.serialize().to_vec(),
    //             input_outpoint: Some(withdrawal_utxo.into()),
    //             output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
    //             output_amount: payout_txout.value.to_sat(),
    //         })
    //         .await;

    //     tracing::info!("Withdrawal response: {:?}", withdrawal_response);

    //     match withdrawal_response {
    //         Ok(_) => break,
    //         Err(e) => tracing::info!("Withdrawal error: {:?}", e),
    //     };

    //     tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    // }

    // Setup tx_sender for sending transactions
    let (op0_db, _) = actors.get_operator_db_and_xonly_pk_by_index(0).await;

    tracing::info!("Waiting for payout is mined and added to db");

    // wait until payout tx is added to db
    poll_until_condition(
        async || {
            Ok(op0_db
                .get_payout_info_from_move_txid(None, move_txid)
                .await
                .is_ok())
        },
        Some(Duration::from_secs(300 * 60)),
        Some(Duration::from_millis(2000)),
    )
    .await
    .wrap_err("Timed out while waiting for payout to be added to db")
    .unwrap();

    let payout_txid = op0_db
        .get_payout_info_from_move_txid(None, move_txid)
        .await
        .unwrap()
        .unwrap()
        .2;

    tracing::info!("Payout txid: {:?}", payout_txid);

    // wait until payout is handled
    poll_until_condition(
        async || {
            Ok(op0_db
                .get_handled_payout_kickoff_txid(None, payout_txid)
                .await?
                .is_some())
        },
        Some(Duration::from_secs(300 * 60)),
        Some(Duration::from_millis(2000)),
    )
    .await
    .wrap_err("Timed out while waiting for payout to be handled")
    .unwrap();

    let kickoff_txid = op0_db
        .get_handled_payout_kickoff_txid(None, payout_txid)
        .await
        .unwrap()
        .expect("Payout must be handled");

    tracing::info!("Kickoff txid: {:?}", kickoff_txid);

    let reimburse_connector = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::ReimburseInKickoff.get_vout(),
    };

    // ensure kickoff tx is on chain
    loop {
        if rpc.is_tx_on_chain(&kickoff_txid).await.unwrap() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }

    tracing::warn!("Ensuring reimburse connector is spent");
    // Ensure the reimburse connector is spent
    loop {
        if rpc.is_utxo_spent(&reimburse_connector).await.unwrap() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }

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
        config.citrea_request_timeout,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );
    let (actors, _deposit_params, move_txid, _deposit_blockhash, _verifiers_public_keys) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
            .await
            .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );
    // rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // Send deposit to Citrea
    let tx = rpc.get_raw_transaction(&move_txid, None).await.unwrap();
    let tx_info = rpc
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc.get_block(&tx_info.blockhash.unwrap()).await.unwrap();
    let _block_height = rpc
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

    let withdrawal_params = WithdrawParams {
        withdrawal_id: 0,
        input_signature: sig.serialize().to_vec(),
        input_outpoint: Some(withdrawal_utxo.into()),
        output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
        output_amount: payout_txout.value.to_sat(),
    };

    let verification_signature = sign_withdrawal_verification_signature::<OptimisticPayoutMessage>(
        &config,
        withdrawal_params.clone(),
    );

    let verification_signature_str = verification_signature.to_string();

    let mut aggregator = actors.get_aggregator();
    // should give err before deposit is confirmed on citrea
    assert!(aggregator
        .optimistic_payout(OptimisticWithdrawParams {
            withdrawal: Some(withdrawal_params.clone()),
            verification_signature: Some(verification_signature_str.clone()),
        })
        .await
        .is_err());

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.get_block_count().await.unwrap();
    citrea_client
        .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
        .await;
    rpc.mine_blocks(5).await.unwrap();

    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    tracing::info!("Collecting deposits and withdrawals");

    // mine 1 block to make sure the withdrawal is in the next block
    // rpc.mine_blocks(1).await.unwrap();

    let current_block_height = rpc.get_block_count().await.unwrap();

    // should give err before withdrawal is confirmed on citrea
    assert!(aggregator
        .optimistic_payout(OptimisticWithdrawParams {
            withdrawal: Some(withdrawal_params.clone()),
            verification_signature: Some(verification_signature_str.clone()),
        })
        .await
        .is_err());

    citrea_client
        .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
        .await;
    // Mine some blocks so that block syncer counts it as finalized
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    tracing::info!("Withdrawal tx sent");

    let opt_payout_tx = poll_get(
        async || {
            let payout_resp = aggregator
                .optimistic_payout(OptimisticWithdrawParams {
                    withdrawal: Some(withdrawal_params.clone()),
                    verification_signature: Some(verification_signature_str.clone()),
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
        config.citrea_request_timeout,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
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
        rpc.get_block_count().await.unwrap()
    );
    // rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // Send deposit to Citrea
    let tx = rpc.get_raw_transaction(&move_txid, None).await.unwrap();
    let tx_info = rpc
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc.get_block(&tx_info.blockhash.unwrap()).await.unwrap();
    let _block_height = rpc
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.get_block_count().await.unwrap();
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

    // Mine some blocks so that block syncer counts it as finalized
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

    let mut operator0 = actors.get_operator_client_by_index(0);
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
        config.citrea_request_timeout,
    )
    .await
    .unwrap();

    tracing::info!("Running deposit");

    tracing::info!(
        "Deposit starting block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );
    let (actors, deposit_info, move_txid, _deposit_blockhash, verifier_pks) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
            .await
            .unwrap();

    // sleep for 1 second
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        "Deposit ending block_height: {:?}",
        rpc.get_block_count().await.unwrap()
    );

    // Send deposit to Citrea
    let tx = rpc.get_raw_transaction(&move_txid, None).await.unwrap();
    let tx_info = rpc
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = rpc.get_block(&tx_info.blockhash.unwrap()).await.unwrap();
    let _block_height = rpc
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    tracing::info!("Depositing to Citrea");
    let current_block_height = rpc.get_block_count().await.unwrap();
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

    // Mine some blocks so that block syncer counts it as finalized
    rpc.mine_blocks(config.protocol_paramset().finality_depth as u64 + 2)
        .await
        .unwrap();

    // operator 0's signer
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let mut operator0 = actors.get_operator_client_by_index(0);
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

    rpc.send_raw_transaction(&spend_tx).await.unwrap();

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

pub async fn make_concurrent_deposits(
    count: usize,
    rpc: &ExtendedBitcoinRpc,
    config: &BridgeConfig,
    verifiers_public_keys: Vec<bitcoin::secp256k1::PublicKey>,
    aggregator: &mut ClementineAggregatorClient<Channel>,
    citrea_client: MockCitreaClient,
) -> eyre::Result<Vec<Txid>> {
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let evm_address = EVMAddress([1; 20]);

    // Create move txs.
    let mut aggregators = (0..count).map(|_| aggregator.clone()).collect::<Vec<_>>();
    let mut move_tx_requests = Vec::new();
    let mut deposit_outpoints = Vec::new();
    for aggregator in aggregators.iter_mut() {
        let (deposit_address, _) =
            get_deposit_address(config, evm_address, verifiers_public_keys.clone()).unwrap();
        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await
            .unwrap();
        deposit_outpoints.push(deposit_outpoint);

        mine_once_after_in_mempool(rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None)
            .await
            .unwrap();

        let deposit_info = DepositInfo {
            deposit_outpoint,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: actor.address.as_unchecked().to_owned(),
            }),
        };
        tracing::debug!(
            "Creating move tx for deposit outpoint: {:?}",
            deposit_info.deposit_outpoint
        );

        let deposit: Deposit = deposit_info.clone().into();
        move_tx_requests.push(aggregator.new_deposit(deposit.clone()));
    }
    let move_txs = try_join_all(move_tx_requests)
        .await
        .unwrap()
        .into_iter()
        .map(|encoded_move_tx| encoded_move_tx.into_inner())
        .collect::<Vec<_>>();
    tracing::debug!("Move txs created: {:?}", move_txs);

    let mut deposit_requests = Vec::new();
    for (i, aggregator) in aggregators.iter_mut().enumerate() {
        let request = SendMoveTxRequest {
            deposit_outpoint: Some(deposit_outpoints[i].into()),
            raw_tx: Some(move_txs[i].clone()),
        };

        deposit_requests.push(aggregator.send_move_to_vault_tx(request.clone()));
    }

    // Send deposit requests at the same time.
    let move_txids: Vec<Txid> = try_join_all(deposit_requests)
        .await
        .unwrap()
        .into_iter()
        .map(|encoded_move_tx| encoded_move_tx.into_inner().try_into().unwrap())
        .collect::<Vec<_>>();
    tracing::debug!("Move txids: {:?}", move_txids);

    sleep(Duration::from_secs(5)).await;
    rpc.mine_blocks(1).await.unwrap();

    for txid in move_txids.iter() {
        let rpc = rpc.clone();
        let txid = *txid;
        poll_until_condition(
            async move || {
                let entry = rpc.get_mempool_entry(&txid).await;
                tracing::debug!("Mempool entry for txid {:?}: {:?}", txid, entry);
                Ok(entry.is_ok())
            },
            Some(Duration::from_secs(120)),
            None,
        )
        .await
        .unwrap();
    }

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    for txid in move_txids.iter() {
        let rpc = rpc.clone();
        let txid = *txid;
        let mut citrea_client = citrea_client.clone();

        poll_until_condition(
            async move || {
                if rpc.get_mempool_entry(&txid).await.is_ok() {
                    return Err(eyre::eyre!(
                        "Txid {:?} still in mempool after mining!",
                        txid
                    ));
                }

                let tx = rpc.get_raw_transaction(&txid, None).await?;

                tracing::debug!("Depositing to Citrea...");

                let current_block_height = rpc.get_block_count().await.unwrap();
                citrea_client
                    .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
                    .await;

                tracing::debug!("Deposit operations are successful.");

                Ok(true)
            },
            None,
            None,
        )
        .await
        .unwrap();
    }

    Ok(move_txids)
}

/// A typical deposit and withdrawal flow. Except each operation are done
/// multiple times and concurrently. This is done by creating multiple requests
/// and `await`ing them together after using [`try_join_all`].
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_deposits_and_withdrawals() {
    let mut config = create_test_config_with_thread_name().await;
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
    let mut aggregator = actors.get_aggregator();

    let verifiers_public_keys: Vec<bitcoin::secp256k1::PublicKey> = aggregator
        .setup(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    let count = 10;

    make_concurrent_deposits(
        count,
        &rpc,
        &config,
        verifiers_public_keys.clone(),
        &mut aggregator,
        citrea_client.clone(),
    )
    .await
    .unwrap();

    let mut sigs = Vec::new();
    let mut withdrawal_utxos = Vec::new();
    let mut payout_txouts = Vec::new();
    for _ in 0..count {
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

        let current_block_height = rpc.get_block_count().await.unwrap();

        citrea_client
            .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
            .await;

        withdrawal_utxos.push(withdrawal_utxo);
        payout_txouts.push(payout_txout);
        sigs.push(sig);
    }

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();
    sleep(Duration::from_secs(10)).await;

    let withdrawal_input_outpoints = withdrawal_utxos.clone();
    let actors_ref = &actors;
    let rpc_ref = &rpc;

    poll_get(
        async move || {
            let mut operators = (0..count)
                .map(|_| {
                    (
                        actors_ref.get_operator_client_by_index(0),
                        actors_ref.get_operator_client_by_index(1),
                    )
                })
                .collect::<Vec<_>>();
            let mut tries = 0;
            loop {
                let mut withdrawal_requests = Vec::new();
                let mut spent_withdrawals = 0;
                for (i, (operator0, operator1)) in operators.iter_mut().enumerate() {
                    // if already spent, skip
                    if rpc_ref.is_utxo_spent(&withdrawal_utxos[i]).await.unwrap() {
                        spent_withdrawals += 1;
                        continue;
                    }
                    let withdraw_params = WithdrawParams {
                        withdrawal_id: i as u32,
                        input_signature: sigs[i].serialize().to_vec(),
                        input_outpoint: Some(withdrawal_utxos[i].into()),
                        output_script_pubkey: payout_txouts[i].script_pubkey.to_bytes(),
                        output_amount: payout_txouts[i].value.to_sat(),
                    };
                    let verification_signature = sign_withdrawal_verification_signature::<
                        OperatorWithdrawalMessage,
                    >(
                        &config, withdraw_params.clone()
                    );

                    let verification_signature_str = verification_signature.to_string();

                    withdrawal_requests.push(operator0.withdraw(WithdrawParamsWithSig {
                        withdrawal: Some(withdraw_params.clone()),
                        verification_signature: Some(verification_signature_str.clone()),
                    }));

                    withdrawal_requests.push(operator1.withdraw(WithdrawParamsWithSig {
                        withdrawal: Some(withdraw_params.clone()),
                        verification_signature: Some(verification_signature_str.clone()),
                    }));
                }
                if withdrawal_requests.is_empty() {
                    return Ok(Some(()));
                }
                tracing::info!(
                    "Withdrawal req replies: {:?}",
                    futures::future::join_all(withdrawal_requests).await
                );
                rpc_ref.mine_blocks(1).await.unwrap();
                tries += 1;
                tracing::info!(
                    "Tries: {:?}, spent_withdrawals: {:?}",
                    tries,
                    spent_withdrawals
                );
                // count number of tries shouldd work at worst case (only 1 withdrawal mined for each try)
                if tries > count + 1 {
                    return Err(eyre::eyre!("Failed to process withdrawals concurrently"));
                }
            }
        },
        Some(Duration::from_secs(240)),
        None,
    )
    .await
    .unwrap();

    tracing::info!("Checking if withdrawal input outpoints are spent");
    // check if withdrawal input outpoints are spent
    for outpoint in withdrawal_input_outpoints.iter() {
        ensure_tx_onchain(&rpc, outpoint.txid).await.unwrap();
        ensure_outpoint_spent(&rpc, *outpoint).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_deposits_and_optimistic_payouts() {
    let mut config = create_test_config_with_thread_name().await;
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
    let mut aggregator = actors.get_aggregator();
    let verifiers_public_keys: Vec<bitcoin::secp256k1::PublicKey> = aggregator
        .setup(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    let count = 10;

    let move_txids = make_concurrent_deposits(
        count,
        &rpc,
        &config,
        verifiers_public_keys.clone(),
        &mut aggregator,
        citrea_client.clone(),
    )
    .await
    .unwrap();

    let mut sigs = Vec::new();
    let mut withdrawal_utxos = Vec::new();
    let mut payout_txouts = Vec::new();
    for _ in 0..count {
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

        let current_block_height = rpc.get_block_count().await.unwrap();

        citrea_client
            .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
            .await;

        withdrawal_utxos.push(withdrawal_utxo);
        payout_txouts.push(payout_txout);
        sigs.push(sig);
    }

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();
    sleep(Duration::from_secs(10)).await;

    poll_until_condition(
        async move || {
            let mut aggregators = (0..count).map(|_| aggregator.clone()).collect::<Vec<_>>();
            let mut withdrawal_requests = Vec::new();

            for (i, aggregator) in aggregators.iter_mut().enumerate() {
                let withdrawal_params = WithdrawParams {
                    withdrawal_id: i as u32,
                    input_signature: sigs[i].serialize().to_vec(),
                    input_outpoint: Some(withdrawal_utxos[i].into()),
                    output_script_pubkey: payout_txouts[i].script_pubkey.to_bytes(),
                    output_amount: payout_txouts[i].value.to_sat(),
                };

                let verification_signature = sign_withdrawal_verification_signature::<
                    OptimisticPayoutMessage,
                >(&config, withdrawal_params.clone());

                let verification_signature_str = verification_signature.to_string();

                withdrawal_requests.push(aggregator.optimistic_payout(OptimisticWithdrawParams {
                    withdrawal: Some(withdrawal_params.clone()),
                    verification_signature: Some(verification_signature_str),
                }));
            }

            let opt_payout_txs = match try_join_all(withdrawal_requests).await {
                Ok(txs) => txs,
                Err(e) => {
                    tracing::error!("Error while processing withdrawals: {:?}", e);
                    return Ok(false);
                }
            };
            tracing::info!("Optimistic payout txs: {:?}", opt_payout_txs);

            Ok(true)
        },
        Some(Duration::from_secs(480)),
        None,
    )
    .await
    .unwrap();

    poll_until_condition(
        async move || {
            tracing::info!("Ensuring move txid bridge deposit is spent");
            for move_txid in move_txids.clone().into_iter() {
                if ensure_outpoint_spent(
                    &rpc,
                    OutPoint {
                        txid: move_txid,
                        vout: (UtxoVout::DepositInMove).get_vout(),
                    },
                )
                .await
                .is_err()
                {
                    return Ok(false);
                }
            }

            Ok(true)
        },
        None,
        None,
    )
    .await
    .unwrap();
}
