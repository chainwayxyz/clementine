//! This module contains integration tests for generating data used in bridge circuit tests.
//!
//! The tests in this file are intended for data generation purposes only and are not meant to be run as part of the standard test suite.
//! They are ignored by default and should be executed manually when bridge-related code changes, to ensure that the generated test data remains up-to-date and consistent with the current implementation.
use super::common::citrea::get_bridge_params;
use crate::bitvm_client::{self, SECP};
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::citrea::{CitreaClient, CitreaClientT, SATS_TO_WEI_MULTIPLIER};
use crate::deposit::KickoffData;

use crate::operator::RoundIndex;
use crate::rpc::clementine::{TransactionRequest, WithdrawParams};
use crate::test::common::citrea::{get_citrea_safe_withdraw_params, SECRET_KEYS};
use crate::test::common::tx_utils::{
    create_tx_sender, ensure_outpoint_spent_while_waiting_for_state_mngr_sync,
    mine_once_after_outpoint_spent_in_mempool,
};
use crate::test::common::tx_utils::{
    get_tx_from_signed_txs_with_type,
    get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync,
};
use crate::test::common::{
    generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool, run_single_deposit,
};
use crate::utils::{initialize_logger, FeePayingType, TxMetadata};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::U256;
use async_trait::async_trait;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

#[derive(PartialEq)]
pub enum BridgeCircuitTestDataVariant {
    HeaderChainProofsWithDiverseLengthsInsufficientTotalWork,
    HeaderChainProofsWithDiverseLengths,
}

struct BridgeCircuitTestData {
    variant: BridgeCircuitTestDataVariant,
}

#[async_trait]
impl TestCase for BridgeCircuitTestData {
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

        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let mut config = create_test_config_with_thread_name().await;

        match self.variant {
            BridgeCircuitTestDataVariant::HeaderChainProofsWithDiverseLengthsInsufficientTotalWork => {
                config
                    .test_params
                    .generate_varying_total_works_insufficient_total_work = true;
            }
            BridgeCircuitTestDataVariant::HeaderChainProofsWithDiverseLengths => {
                config.test_params.generate_varying_total_works = true;
            }
        }

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

        let block_count = da.get_block_count().await?;
        tracing::debug!("Block count before deposit: {:?}", block_count);

        tracing::info!(
            "Deposit starting at block height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (actors, deposit_params, move_txid, _deposit_blockhash, _verifiers_public_keys) =
            run_single_deposit::<CitreaClient>(&mut config, rpc.clone(), None, None, None).await?;
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
        let mut operator0 = actors.get_operator_client_by_index(0);

        // Without a withdrawal in Citrea, operator can't withdraw.
        assert!(operator0
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

        let (op0_db, op0_xonly_pk) = actors.get_operator_db_and_xonly_pk_by_index(0).await;

        loop {
            let withdrawal_response = operator0
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
                Ok(_) => break,
                Err(e) => tracing::info!("Withdrawal error: {:?}", e),
            };

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            rpc.mine_blocks_while_synced(1, &actors).await.unwrap();
        }

        let payout_txid = get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync(
            &rpc,
            lc_prover,
            withdrawal_utxo,
            &actors,
        )
        .await
        .unwrap();

        rpc.mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, &actors)
            .await
            .unwrap();

        // wait until payout is handled
        tracing::info!("Waiting until payout is handled");
        while op0_db
            .get_handled_payout_kickoff_txid(None, payout_txid)
            .await?
            .is_none()
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let kickoff_txid = op0_db
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
        let all_txs = operator0
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
        ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
            &rpc,
            lc_prover,
            reimburse_connector,
            &actors,
        )
        .await
        .unwrap();

        // Create assert transactions for operator 0
        let assert_txs = operator0
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

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_diverse_hcp_lengths() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::HeaderChainProofsWithDiverseLengths,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_insuff_total_work_diverse_hcp_lens() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );

    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant:
            BridgeCircuitTestDataVariant::HeaderChainProofsWithDiverseLengthsInsufficientTotalWork,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}
