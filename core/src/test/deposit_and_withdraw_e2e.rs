use super::common::citrea::get_bridge_params;
use crate::actor::Actor;
use crate::bitvm_client::{self, SECP};
use crate::builder::address::create_taproot_address;
use crate::builder::script::SpendPath;
use crate::builder::transaction::input::{SpendableTxIn, UtxoVout};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
use crate::citrea::{CitreaClient, CitreaClientT, SATS_TO_WEI_MULTIPLIER};
use crate::config::protocol::{self, ProtocolParamset};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{self, BaseDepositData, DepositInfo, DepositType, KickoffData};
use crate::errors::ResultExt;
use crate::header_chain_prover::HeaderChainProver;
use crate::operator::RoundIndex;
use crate::rpc::clementine::{
    Deposit, Empty, FeeType, FinalizedPayoutParams, KickoffId, NormalSignatureKind, RawSignedTx,
    SendMoveTxRequest, SendTxRequest, TransactionRequest, WithdrawParams, WithdrawResponse,
};
use crate::test::common::citrea::{get_citrea_safe_withdraw_params, MockCitreaClient, SECRET_KEYS};
use crate::test::common::tx_utils::{
    create_tx_sender, ensure_outpoint_spent,
    ensure_outpoint_spent_while_waiting_for_light_client_sync, ensure_tx_onchain,
    get_txid_where_utxo_is_spent, mine_once_after_outpoint_spent_in_mempool,
};
use crate::test::common::tx_utils::{
    get_tx_from_signed_txs_with_type, wait_for_fee_payer_utxos_to_be_in_mempool,
};
use crate::test::common::{
    create_actors, create_regtest_rpc, generate_withdrawal_transaction_and_signature,
    get_deposit_address, mine_once_after_in_mempool, poll_get, poll_until_condition,
    run_single_deposit,
};
use crate::utils::{initialize_logger, FeePayingType, TxMetadata};
use crate::{aggregator, EVMAddress, UTXO};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::{U256, U32};
use alloy::rpc::types::request;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, PublicKey, Transaction, TxOut, Txid};
use bitcoincore_rpc::RpcApi;
use bitvm::groth16::constants::R;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
};
use eyre::Context;
use futures::future::join_all;
use futures::future::try_join_all;
use once_cell::sync::{Lazy, OnceCell};
use secp256k1::SECP256K1;
use serde::Serialize;
use sha2::digest::generic_array::sequence;
use statig::Response::Transition;
use std::time::Duration;
use tokio::time::sleep;
use tonic::{Request, Response, Status};

pub static PROTOCOL_PARAMSET: OnceCell<ProtocolParamset> = OnceCell::new();

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

        rpc.mine_blocks(12).await.unwrap();

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

        let block_count = da.get_block_count().await?;
        tracing::debug!("Block count before deposit: {:?}", block_count);

        tracing::info!(
            "Deposit starting at block height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (
            _verifiers,
            mut operators,
            mut _aggregator,
            _cleanup,
            deposit_params,
            move_txid,
            _deposit_blockhash,
            verifiers_public_keys,
        ) = run_single_deposit::<CitreaClient>(&mut config, rpc.clone(), None, None).await?;
        tracing::info!(
            "Deposit ending block_height: {:?}",
            rpc.client.get_block_count().await?
        );

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
            &rpc,
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().unwrap(),
            tx,
        )
        .await?;

        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        // Wait for the deposit to be processed.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

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

        rpc.mine_blocks(1).await.unwrap();

        let block_height = rpc.client.get_block_count().await.unwrap();

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        citrea::wait_until_lc_contract_updated(sequencer.client.http_client(), block_height)
            .await
            .unwrap();

        let params = get_citrea_safe_withdraw_params(
            &rpc,
            withdrawal_utxo_with_txout.clone(),
            payout_txout.clone(),
            sig,
        )
        .await
        .unwrap();

        tracing::info!("Params: {:?}", params);

        let withdrawal_utxo = withdrawal_utxo_with_txout.outpoint;
        tracing::debug!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

        // Without a withdrawal in Citrea, operator can't withdraw.
        assert!(operators[0]
            .withdraw(WithdrawParams {
                withdrawal_id: 0,
                input_signature: sig.serialize().to_vec(),
                input_outpoint: Some(withdrawal_utxo.into()),
                output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                output_amount: payout_txout.value.to_sat(),
            })
            .await
            .is_err());

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .await
        .unwrap();

        // let citrea_withdrawal_tx = citrea_client
        //     .contract
        //     .withdraw(
        //         FixedBytes::from(withdrawal_utxo.txid.to_raw_hash().to_byte_array()),
        //         FixedBytes::from(withdrawal_utxo.vout.to_be_bytes()),
        //     )
        //     .value(U256::from(
        //         config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
        //     ))
        //     .send()
        //     .await
        //     .unwrap();
        // tracing::debug!("Withdrawal TX sent in Citrea");

        // // 1. force sequencer to commit
        // for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
        //     sequencer.client.send_publish_batch_request().await.unwrap();
        // }
        // tracing::debug!("Publish batch request sent");

        // let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
        // println!("Citrea withdrawal tx receipt: {:?}", receipt);

        let citrea_withdrawal_tx = citrea_client
            .contract
            .safeWithdraw(params.0, params.1, params.2, params.3, params.4)
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

        let payout_txid = loop {
            let withdrawal_response = operators[0]
                .withdraw(WithdrawParams {
                    withdrawal_id: 0,
                    input_signature: sig.serialize().to_vec(),
                    input_outpoint: Some(withdrawal_utxo.into()),
                    output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                    output_amount: payout_txout.value.to_sat(),
                })
                .await;

            tracing::info!("Withdrawal response: {:?}", withdrawal_response);

            match withdrawal_response {
                Ok(withdrawal_response) => {
                    tracing::info!("Withdrawal response: {:?}", withdrawal_response);
                    break Txid::from_byte_array(
                        withdrawal_response
                            .into_inner()
                            .txid
                            .unwrap()
                            .txid
                            .try_into()
                            .unwrap(),
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
            vout: UtxoVout::ReimburseInKickoff.get_vout(),
        };

        let kickoff_block_height =
            mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(300)).await?;

        let kickoff_tx = rpc.get_tx_of_txid(&kickoff_txid).await?;

        // wrongfully challenge operator
        let kickoff_idx = kickoff_tx.input[0].previous_output.vout - 1;
        let base_tx_req = TransactionRequest {
            kickoff_id: Some(
                KickoffData {
                    operator_xonly_pk: op0_xonly_pk,
                    round_idx: RoundIndex::Round(0),
                    kickoff_idx: kickoff_idx as u32,
                }
                .into(),
            ),
            deposit_outpoint: Some(deposit_params.deposit_outpoint.into()),
        };
        let all_txs = operators[0]
            .internal_create_signed_txs(base_tx_req.clone())
            .await?
            .into_inner();

        let challenge_tx = bitcoin::consensus::deserialize(
            &all_txs
                .signed_txs
                .iter()
                .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
                .unwrap()
                .raw_tx,
        )
        .unwrap();

        let kickoff_tx: Transaction = bitcoin::consensus::deserialize(
            &all_txs
                .signed_txs
                .iter()
                .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
                .unwrap()
                .raw_tx,
        )
        .unwrap();

        assert_eq!(kickoff_txid, kickoff_tx.compute_txid());

        // send wrong challenge tx
        let (tx_sender, tx_sender_db) = create_tx_sender(&config, 0).await.unwrap();
        let mut db_commit = tx_sender_db.begin_transaction().await.unwrap();
        tx_sender
            .insert_try_to_send(
                &mut db_commit,
                Some(TxMetadata {
                    deposit_outpoint: None,
                    operator_xonly_pk: None,
                    round_idx: None,
                    kickoff_idx: None,
                    tx_type: TransactionType::Challenge,
                }),
                &challenge_tx,
                FeePayingType::RBF,
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        db_commit.commit().await.unwrap();

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let challenge_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Challenge.get_vout(),
        };
        tracing::warn!(
            "Wait until challenge tx is in mempool, kickoff block height: {:?}",
            kickoff_block_height
        );
        // wait until challenge tx is in mempool
        mine_once_after_outpoint_spent_in_mempool(&rpc, challenge_outpoint)
            .await
            .unwrap();
        tracing::warn!("Mined once after challenge tx is in mempool");

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

        // Create assert transactions for operator 0
        let assert_txs = operators[0]
            .internal_create_assert_commitment_txs(base_tx_req)
            .await?
            .into_inner();

        // check if asserts were sent due to challenge
        let operator_assert_txids = (0
            ..bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs())
            .map(|i| {
                let assert_tx =
                    get_tx_from_signed_txs_with_type(&assert_txs, TransactionType::MiniAssert(i))
                        .unwrap();
                assert_tx.compute_txid()
            })
            .collect::<Vec<Txid>>();
        for (idx, txid) in operator_assert_txids.into_iter().enumerate() {
            assert!(
                rpc.is_tx_on_chain(&txid).await.unwrap(),
                "Mini assert {} was not found in the chain",
                idx
            );
        }
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
async fn citrea_deposit_and_withdraw_e2e() -> citrea_e2e::Result<()> {
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
async fn citrea_deposit_and_withdraw_e2e_non_zero_genesis_height() -> citrea_e2e::Result<()> {
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
    let (
        _verifiers,
        mut operators,
        _aggregator,
        _cleanup,
        _deposit_params,
        move_txid,
        _deposit_blockhash,
        verifiers_public_keys,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None)
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

    let payout_txid = poll_get(
        async || {
            let withdrawal_response = operators[0]
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
    let (
        _verifiers,
        _operators,
        mut aggregator,
        _cleanup,
        _deposit_params,
        move_txid,
        _deposit_blockhash,
        _verifiers_public_keys,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None)
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
    let (
        _verifiers,
        mut operators,
        _aggregator,
        _cleanup,
        deposit_info,
        move_txid,
        _deposit_blockhash,
        _,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None)
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
    let (
        _verifiers,
        mut operators,
        mut aggregator,
        _cleanup,
        deposit_info,
        move_txid,
        _deposit_blockhash,
        verifier_pks,
    ) = run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None)
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

#[tokio::test]
async fn concurrent_deposits_and_withdrawals() {
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

    let (verifiers, mut operators, mut aggregator, cleanup) =
        create_actors::<MockCitreaClient>(&mut config).await;
    let verifiers_public_keys: Vec<bitcoin::secp256k1::PublicKey> = aggregator
        .setup(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let count = 10;
    let evm_address = EVMAddress([1; 20]);

    // Prepare deposit requests.
    let mut aggregators = (0..count).map(|_| aggregator.clone()).collect::<Vec<_>>();
    let mut deposit_requests = Vec::new();
    for (i, mut aggregator) in aggregators.iter_mut().enumerate() {
        let (deposit_address, _) =
            get_deposit_address(&config, evm_address, verifiers_public_keys.clone()).unwrap();
        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await
            .unwrap();

        mine_once_after_in_mempool(&rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None)
            .await
            .unwrap();
        let deposit_blockhash = rpc
            .get_blockhash_of_tx(&deposit_outpoint.txid)
            .await
            .unwrap();

        let deposit_info = DepositInfo {
            deposit_outpoint,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: actor.address.as_unchecked().to_owned(),
            }),
        };

        let deposit: Deposit = deposit_info.clone().into();

        let movetx = aggregator
            .clone()
            .new_deposit(deposit.clone())
            .await
            .unwrap();
        let request = SendMoveTxRequest {
            deposit_outpoint: Some(deposit_outpoint.into()),
            raw_tx: Some(movetx.into_inner()),
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
    println!("Move txids: {:?}", move_txids);

    sleep(Duration::from_secs(5)).await;
    rpc.mine_blocks(1).await.unwrap();

    for txid in move_txids.iter() {
        let rpc = rpc.clone();
        let txid = *txid;
        poll_until_condition(
            async move || {
                let entry = rpc.client.get_mempool_entry(&txid).await;
                println!("Mempool entry for txid {:?}: {:?}", txid, entry);
                Ok(entry.is_ok())
            },
            Some(Duration::from_secs(120)),
            None,
        )
        .await
        .unwrap();
    }

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    for (i, txid) in move_txids.iter().enumerate() {
        let rpc = rpc.clone();
        let txid = *txid;
        let evm_address = evm_address.clone();
        let mut citrea_client = citrea_client.clone();

        poll_until_condition(
            async move || {
                if rpc.client.get_mempool_entry(&txid).await.is_ok() {
                    return Err(eyre::eyre!(
                        "Txid {:?} still in mempool after mining!",
                        txid
                    ));
                }

                let tx = rpc.client.get_raw_transaction(&txid, None).await?;
                let tx_info = rpc.client.get_raw_transaction_info(&txid, None).await?;
                let block = rpc.client.get_block(&tx_info.blockhash.unwrap()).await?;
                let block_height =
                    rpc.client.get_block_info(&block.block_hash()).await?.height as u64;

                println!("Depositing to Citrea...");

                let current_block_height = rpc.client.get_block_count().await.unwrap();
                citrea_client
                    .insert_deposit_move_txid(current_block_height + 1, tx.compute_txid())
                    .await;

                println!("Deposit operations are successful.");

                Ok(true)
            },
            None,
            None,
        )
        .await
        .unwrap();
    }

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

        let current_block_height = rpc.client.get_block_count().await.unwrap();

        citrea_client
            .insert_withdrawal_utxo(current_block_height + 1, withdrawal_utxo)
            .await;

        withdrawal_utxos.push(withdrawal_utxo);
        payout_txouts.push(payout_txout);
        sigs.push(sig);
    }

    sleep(Duration::from_secs(5)).await;
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    poll_until_condition(
        {
            let operators = operators.clone();
            let sigs = sigs.clone();
            let withdrawal_utxos = withdrawal_utxos.clone();
            let payout_txouts = payout_txouts.clone();
            let mut operator0s = (0..count).map(|_| operators[0].clone()).collect::<Vec<_>>();

            async move || {
                let mut withdrawal_requests = Vec::new();

                for (i, mut operator) in operator0s.iter_mut().enumerate() {
                    withdrawal_requests.push(operator.withdraw(WithdrawParams {
                        withdrawal_id: i as u32,
                        input_signature: sigs[i].serialize().to_vec(),
                        input_outpoint: Some(withdrawal_utxos[i].into()),
                        output_script_pubkey: payout_txouts[i].script_pubkey.to_bytes(),
                        output_amount: payout_txouts[i].value.to_sat(),
                    }));
                }

                let withdrawal_txids = match try_join_all(withdrawal_requests).await {
                    Ok(txids) => txids,
                    Err(e) => {
                        tracing::error!("error while processing withdrawals: {:?}", e);
                        return Ok(false);
                    }
                };

                let withdrawal_txids: Vec<Txid> = withdrawal_txids
                    .into_iter()
                    .map(|encoded_withdrawal_tx| {
                        encoded_withdrawal_tx
                            .into_inner()
                            .txid
                            .unwrap()
                            .try_into()
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                println!("Withdrawal txids: {:?}", withdrawal_txids);

                Ok(true)
            }
        },
        None,
        None,
    )
    .await
    .unwrap();
}
