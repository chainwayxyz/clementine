use super::common::citrea::BRIDGE_PARAMS;
use crate::bitvm_client::SECP;
use crate::citrea::{CitreaClient, SATS_TO_WEI_MULTIPLIER};
use crate::test::common::citrea::SECRET_KEYS;
use crate::test::common::{generate_withdrawal_transaction_and_signature, run_single_deposit};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::FixedBytes;
use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
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
            initial_da_height: 100,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (sequencer, full_node, lc_prover, _, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();
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

        let (
            _verifiers,
            _operators,
            _aggregator,
            _watchtowers,
            _cleanup,
            _deposit_outpoint,
            move_txid,
        ) = run_single_deposit(&mut config, rpc.clone(), None).await?;
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

        // Send deposit to Citrea
        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc.client.get_block(&tx_info.blockhash.unwrap()).await?;
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height as u64;

        // citrea::sync_citrea_l2(&rpc, sequencer, full_node).await;

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
        let withdrawal_utxo = generate_withdrawal_transaction_and_signature(
            &config,
            &rpc,
            &withdrawal_address,
            Amount::from_sat(330),
        )
        .await
        .0
        .outpoint;
        println!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

        let citrea_client = CitreaClient::new(
            Url::parse(&config.citrea_rpc_url).unwrap(),
            Url::parse(&config.citrea_light_client_prover_url).unwrap(),
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .unwrap();

        tracing::error!("Collecting deposits and withdrawals");

        // let current_l2_height = sequencer
        //     .client
        //     .ledger_get_head_soft_confirmation_height()
        //     .await?;

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

        tracing::error!("Withdrawal tx sent");

        // 1. force sequencer to commit
        for _ in 0..sequencer.config.node.min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        tracing::error!("Publish batch request sent");

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

        tracing::error!("Finalized height: {:?}", finalized_height);
        lc_prover.wait_for_l1_height(finalized_height, None).await?;
        tracing::error!("Waited for L1 height");

        loop {
            // mine 1 block
            rpc.mine_blocks(1).await.unwrap();
            // wait 100ms
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }

        // TODO: Send withdrawal signatures to operator.

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
