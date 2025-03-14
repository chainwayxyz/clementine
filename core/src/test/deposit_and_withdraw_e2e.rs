use super::common::citrea::BRIDGE_PARAMS;
use crate::bitvm_client::SECP;
use crate::citrea::{CitreaClient, SATS_TO_WEI_MULTIPLIER};
use crate::database::Database;
use crate::rpc::clementine::WithdrawParams;
use crate::test::common::citrea::SECRET_KEYS;
use crate::test::common::{
    generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool, run_single_deposit,
};
use crate::test::full_flow::{ensure_outpoint_spent, ensure_tx_onchain};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::FixedBytes;
use alloy::primitives::U256;
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

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
            bridge_initialize_params: BRIDGE_PARAMS.to_string(),
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
            initial_da_height: 200,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, _, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();
        let block_count = da.get_block_count().await?;
        println!("Block count before deposit: {:?}", block_count);
        let lc_prover = lc_prover.unwrap();

        let mut config = create_test_config_with_thread_name(None).await;
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

        tracing::info!("Running deposit");

        tracing::info!(
            "Deposit starting block_height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (
            _verifiers,
            mut operators,
            _aggregator,
            _watchtowers,
            _cleanup,
            _deposit_outpoint,
            move_txid,
        ) = run_single_deposit(&mut config, rpc.clone(), None).await?;

        tracing::info!(
            "Deposit ending block_height: {:?}",
            rpc.client.get_block_count().await?
        );
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        // sleep for 1 second
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        for _ in 0..sequencer.config.node.min_soft_confirmations_per_commitment {
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

        // citrea::sync_citrea_l2(&rpc, sequencer, full_node).await;

        tracing::info!("Depositing to Citrea");
        citrea::deposit(
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().unwrap(),
            tx,
        )
        .await?;

        for _ in 0..sequencer.config.node.min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        // Make a withdrawal

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

        println!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

        let citrea_client = CitreaClient::new(
            Url::parse(&config.citrea_rpc_url).unwrap(),
            Url::parse(&config.citrea_light_client_prover_url).unwrap(),
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .unwrap();

        tracing::info!("Collecting deposits and withdrawals");

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

        tracing::info!("Withdrawal tx sent");

        // 1. force sequencer to commit
        for _ in 0..sequencer.config.node.min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        tracing::info!("Publish batch request sent");

        let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
        println!("Citrea withdrawal tx receipt: {:?}", receipt);

        // 2. wait until 2 commitment txs (commit, reveal) seen from DA to ensure their reveal prefix nonce is found
        da.wait_mempool_len(2, None).await?;

        // 3. generate FINALITY_DEPTH da blocks
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        // 4. wait for batch prover to generate proof on the finalized height
        // 5. ensure 2 batch proof txs on DA (commit, reveal)
        da.wait_mempool_len(2, None).await?;

        // 6. generate FINALITY_DEPTH da blocks
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();

        tracing::info!("Finalized height: {:?}", finalized_height);
        lc_prover.wait_for_l1_height(finalized_height, None).await?;
        tracing::info!("Waited for L1 height");

        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH + 2).await.unwrap();

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

            // wait 1000ms
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        };

        tracing::info!("Payout txid: {:?}", payout_txid);

        mine_once_after_in_mempool(&rpc, payout_txid, Some("Payout tx"), None).await?;

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

        // wait until payout part is not null
        while db
            .get_first_unhandled_payout_by_operator_id(None, 0)
            .await?
            .is_none()
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tracing::info!("Waiting until payout is handled");
        // wait until payout is handled
        while db
            .get_first_unhandled_payout_by_operator_id(None, 0)
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

        // Wait for the kickoff tx to be onchain
        ensure_tx_onchain(&rpc, kickoff_txid).await.unwrap();

        // Ensure the reimburse connector is spent
        ensure_outpoint_spent(&rpc, reimburse_connector)
            .await
            .unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn citrea_deposit_and_withdraw_e2e() -> Result<()> {
    // TODO: temp hack to use the correct docker image
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:60d9fd633b9e62b647039f913c6f7f8c085ad42e",
    );
    TestCaseRunner::new(CitreaDepositAndWithdrawE2E).run().await
}
