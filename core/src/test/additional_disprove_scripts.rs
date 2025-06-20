use super::common::citrea::get_bridge_params;
use super::common::ActorsCleanup;
use crate::bitvm_client::SECP;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::citrea::{CitreaClient, CitreaClientT, SATS_TO_WEI_MULTIPLIER};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::KickoffData;
use crate::operator::RoundIndex;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::{TransactionRequest, WithdrawParams};
use crate::test::common::citrea::{get_citrea_safe_withdraw_params, SECRET_KEYS};
use crate::test::common::tx_utils::{
    create_tx_sender, ensure_outpoint_spent_while_waiting_for_light_client_sync,
    get_tx_from_signed_txs_with_type,
    get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync,
    mine_once_after_outpoint_spent_in_mempool,
};
use crate::test::common::{
    generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool, run_single_deposit,
};
use crate::utils::{FeePayingType, TxMetadata};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::U256;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::node::Node;
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use tonic::transport::Channel;
pub enum TestVariant {
    HealthyState,
    CorruptedLatestBlockHash,
    CorruptedPayoutTxBlockHash,
    CorruptedChallengeSendingWatchtowers,
    OperatorForgotWatchtowerChallenge,
}

struct AdditionalDisproveTest {
    variant: TestVariant,
}

impl AdditionalDisproveTest {
    async fn common_test_setup(
        &self,
        mut config: BridgeConfig,
        lc_prover: &Node<LightClientProverConfig>,
        batch_prover: &Node<BatchProverConfig>,
        da: &BitcoinNode,
        sequencer: &Node<SequencerConfig>,
    ) -> Result<(
        Transaction,
        ExtendedRpc,
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        ActorsCleanup,
    )> {
        tracing::debug!(
            "disprove timeout is set to: {:?}",
            config.protocol_paramset().disprove_timeout_timelock
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
            verifiers,
            mut operators,
            aggregator,
            cleanup,
            deposit_params,
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

        // After the deposit, the balance should be non-zero.
        assert_ne!(
            citrea::eth_get_balance(
                sequencer.client.http_client().clone(),
                crate::EVMAddress([1; 20]),
            )
            .await
            .unwrap(),
            0,
            "Balance should be non-zero after deposit"
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

        // Wait for TXs to be on-chain (CPFP etc.).
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

        let withdrawal_utxo = withdrawal_utxo_with_txout.outpoint;

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
                            .ok_or(eyre::eyre!("Malformed outpoint in withdrawal response"))
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

        tracing::info!("Kickoff txid: {:?}", kickoff_txid);

        // Wait for the kickoff tx to be onchain
        let kickoff_block_height =
            mine_once_after_in_mempool(&rpc, kickoff_txid, Some("Kickoff tx"), Some(300)).await?;

        let kickoff_tx = rpc.get_tx_of_txid(&kickoff_txid).await?;

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

        let first_assert_utxo = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Assert(0).get_vout(),
        };

        ensure_outpoint_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            first_assert_utxo,
        )
        .await
        .unwrap();

        let assert_txs = operators[0]
            .internal_create_assert_commitment_txs(base_tx_req)
            .await?
            .into_inner();

        let assert_tx =
            get_tx_from_signed_txs_with_type(&assert_txs, TransactionType::MiniAssert(0)).unwrap();
        let txid = assert_tx.compute_txid();

        assert!(
            rpc.is_tx_on_chain(&txid).await.unwrap(),
            "Mini assert 0 was not found in the chain",
        );

        Ok((kickoff_tx, rpc, verifiers, operators, aggregator, cleanup))
    }

    async fn disrupted_latest_block_hash_commit(&self, f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;
        config.test_params.disrupt_latest_block_hash_commit = true;

        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let (kickoff_tx, rpc, _verifiers, _operators, _aggregator, _cleanup) = self
            .common_test_setup(config, lc_prover, batch_prover, da, sequencer)
            .await?;

        tracing::info!("Common test setup completed");

        let kickoff_txid = kickoff_tx.compute_txid();

        let disprove_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Disprove.get_vout(),
        };

        tracing::info!(
            "Disprove outpoint: {:?}, txid: {:?}",
            disprove_outpoint,
            kickoff_txid
        );

        let disprove_txid = get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            disprove_outpoint,
        )
        .await
        .unwrap();

        tracing::info!("Disprove txid: {:?}", disprove_txid);

        let round_txid = kickoff_tx.input[0].previous_output.txid;

        let burn_connector = OutPoint {
            txid: round_txid,
            vout: UtxoVout::CollateralInRound.get_vout(),
        };

        let disprove_tx = rpc.client.get_raw_transaction(&disprove_txid, None).await?;

        assert!(
            disprove_tx.input[1].previous_output == burn_connector,
            "Additional disprove tx input does not match burn connector outpoint"
        );

        assert_eq!(
            disprove_tx.input[0].witness.len(), 560,
            "Additional disprove tx input witness length is not 560 bytes"
        );

        tracing::info!("Disprove transaction is onchain");
        Ok(())
    }

    async fn disrupted_payout_tx_block_hash_commit(&self, f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;
        config.test_params.disrupt_payout_tx_block_hash_commit = true;

        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let (kickoff_tx, rpc, _verifiers, _operators, _aggregator, _cleanup) = self
            .common_test_setup(config, lc_prover, batch_prover, da, sequencer)
            .await?;

        tracing::info!("Common test setup completed");

        let kickoff_txid = kickoff_tx.compute_txid();

        let disprove_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Disprove.get_vout(),
        };

        tracing::info!(
            "Disprove outpoint: {:?}, txid: {:?}",
            disprove_outpoint,
            kickoff_txid
        );

        let txid = get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            disprove_outpoint,
        )
        .await
        .unwrap();

        tracing::info!("Disprove txid: {:?}", txid);

        let round_txid = kickoff_tx.input[0].previous_output.txid;

        let burn_connector = OutPoint {
            txid: round_txid,
            vout: UtxoVout::CollateralInRound.get_vout(),
        };

        let disprove_tx = rpc.client.get_raw_transaction(&txid, None).await?;

        assert!(
            disprove_tx.input[1].previous_output == burn_connector,
            "Additional disprove tx input does not match burn connector outpoint"
        );

        assert_eq!(
            disprove_tx.input[0].witness.len(), 560,
            "Additional disprove tx input witness length is not 560 bytes"
        );

        tracing::info!("Disprove transaction is onchain");
        Ok(())
    }

    async fn disrupted_challenge_sending_watchtowers_commit(
        &self,
        f: &mut TestFramework,
    ) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .disrupt_challenge_sending_watchtowers_commit = true;

        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let (kickoff_tx, rpc, _verifiers, _operators, _aggregator, _cleanup) = self
            .common_test_setup(config, lc_prover, batch_prover, da, sequencer)
            .await?;

        tracing::info!("Common test setup completed");

        let kickoff_txid = kickoff_tx.compute_txid();

        let disprove_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Disprove.get_vout(),
        };

        tracing::info!(
            "Disprove outpoint: {:?}, txid: {:?}",
            disprove_outpoint,
            kickoff_txid
        );

        let txid = get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            disprove_outpoint,
        )
        .await
        .unwrap();

        tracing::info!("Disprove txid: {:?}", txid);

        let round_txid = kickoff_tx.input[0].previous_output.txid;

        let burn_connector = OutPoint {
            txid: round_txid,
            vout: UtxoVout::CollateralInRound.get_vout(),
        };

        let disprove_tx = rpc.client.get_raw_transaction(&txid, None).await?;

        assert!(
            disprove_tx.input[1].previous_output == burn_connector,
            "Additional disprove tx input does not match burn connector outpoint"
        );

        assert_eq!(
            disprove_tx.input[0].witness.len(), 560,
            "Additional disprove tx input witness length is not 560 bytes"
        );

        tracing::info!("Disprove transaction is onchain");
        Ok(())
    }

    async fn operator_forgot_watchtower_challenge(&self, f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;
        config.test_params.operator_forgot_watchtower_challenge = true;

        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let (kickoff_tx, rpc, _verifiers, _operators, _aggregator, _cleanup) = self
            .common_test_setup(config, lc_prover, batch_prover, da, sequencer)
            .await?;

        tracing::info!("Common test setup completed");

        let kickoff_txid = kickoff_tx.compute_txid();

        let disprove_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Disprove.get_vout(),
        };

        tracing::info!(
            "Disprove outpoint: {:?}, txid: {:?}",
            disprove_outpoint,
            kickoff_txid
        );

        let txid = get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            disprove_outpoint,
        )
        .await
        .unwrap();

        tracing::info!("Disprove txid: {:?}", txid);

        let round_txid = kickoff_tx.input[0].previous_output.txid;

        let burn_connector = OutPoint {
            txid: round_txid,
            vout: UtxoVout::CollateralInRound.get_vout(),
        };

        let disprove_tx = rpc.client.get_raw_transaction(&txid, None).await?;

        assert!(
            disprove_tx.input[1].previous_output == burn_connector,
            "Additional disprove tx input does not match burn connector outpoint"
        );

        assert_eq!(
            disprove_tx.input[0].witness.len(), 560,
            "Additional disprove tx input witness length is not 560 bytes"
        );

        tracing::info!("Disprove transaction is onchain");
        Ok(())
    }

    async fn healthy_state_test(&self, f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;

        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da,
            sequencer,
            Some((
                lc_prover.config.rollup.rpc.bind_host.as_str(),
                lc_prover.config.rollup.rpc.bind_port,
            )),
        );

        let (kickoff_tx, rpc, _verifiers, _operators, _aggregator, _cleanup) = self
            .common_test_setup(config, lc_prover, batch_prover, da, sequencer)
            .await?;

        tracing::info!("Common test setup completed");

        let kickoff_txid = kickoff_tx.compute_txid();

        let disprove_timeout_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Disprove.get_vout(),
        };

        tracing::info!(
            "Disprove timeout outpoint: {:?}, txid: {:?}",
            disprove_timeout_outpoint,
            kickoff_txid
        );

        let txid = get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync(
            &rpc,
            lc_prover,
            disprove_timeout_outpoint,
        )
        .await
        .unwrap();

        tracing::info!("Disprove timeout txid: {:?}", txid);

        let kickoff_finalizer_out = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::KickoffFinalizer.get_vout(),
        };

        let disprove_timeout_tx = rpc.client.get_raw_transaction(&txid, None).await?;

        assert!(
            disprove_timeout_tx.input[1].previous_output == kickoff_finalizer_out,
            "Disprove timeout tx input does not match kickoff finalizer outpoint"
        );

        tracing::info!("Disprove timeout transaction is onchain");
        Ok(())
    }
}

#[async_trait]
impl TestCase for AdditionalDisproveTest {
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
        match self.variant {
            TestVariant::HealthyState => {
                tracing::info!("Running healthy state test");
                self.healthy_state_test(f).await?;
            }
            TestVariant::CorruptedLatestBlockHash => {
                tracing::info!("Running disrupted latest block hash commit test");
                self.disrupted_latest_block_hash_commit(f).await?;
            }
            TestVariant::CorruptedPayoutTxBlockHash => {
                tracing::info!("Running disrupted payout tx block hash commit test");
                self.disrupted_payout_tx_block_hash_commit(f).await?;
            }
            TestVariant::CorruptedChallengeSendingWatchtowers => {
                tracing::info!("Running disrupted challenge sending watchtowers commit test");
                self.disrupted_challenge_sending_watchtowers_commit(f)
                    .await?;
            }
            TestVariant::OperatorForgotWatchtowerChallenge => {
                tracing::info!("Running operator forgot watchtower challenge test");
                self.operator_forgot_watchtower_challenge(f).await?;
            }
        }

        Ok(())
    }
}

/// Tests the disprove mechanism when the latest block hash commitment is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `disrupt_latest_block_hash_commit = true` to simulate a corrupted block hash during commitment.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted block hash in the commitment.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_disrupted_latest_block_hash() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedLatestBlockHash,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove timeout mechanism in a healthy, non-disrupted protocol state.
///
/// # Arrange
/// * Sets up full Citrea stack with sequencer, DA node, batch prover, and light client prover.
/// * Uses default bridge configuration without any intentional disruption.
///
/// # Act
/// * Executes deposit and withdrawal flows.
/// * Processes the payout and kickoff transactions.
/// * Waits for the disprove timeout to activate.
///
/// # Assert
/// * Confirms that a disprove timeout transaction is created and included on Bitcoin.
/// * Verifies that the transaction correctly spends the `KickoffFinalizer` output.
#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_healthy() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::HealthyState,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when the payout transaction's block hash commitment is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `disrupt_payout_tx_block_hash_commit = true` to simulate a corrupted block hash for the payout transaction during commitment.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted payout transaction block hash in the commitment.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_disrupted_payout_tx_block_hash() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedPayoutTxBlockHash,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when the commitment for challenges sent by watchtowers is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `disrupt_challenge_sending_watchtowers_commit = true` to simulate a corrupted commitment related to watchtower challenges.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted watchtower challenge commitment.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_disrupt_chal_sending_wts() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedChallengeSendingWatchtowers,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when an operator "forgets" to include a watchtower challenge.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `operator_forgot_watchtower_challenge = true` to simulate a scenario where an operator fails to send a necessary watchtower challenge.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the operator's failure to include a watchtower challenge.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_operator_forgot_wt_challenge() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::OperatorForgotWatchtowerChallenge,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}
