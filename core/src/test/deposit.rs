use super::common::citrea::BRIDGE_PARAMS;
use crate::{
    citrea::{CitreaClient, LightClientProverRpcClient, SATS_TO_WEI_MULTIPLIER},
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self, SECRET_KEYS},
        create_test_config_with_thread_name, run_single_deposit,
    },
    EVMAddress,
};
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    config::{
        BatchProverConfig, BitcoinConfig, LightClientProverConfig, SequencerConfig, TestCaseConfig,
        TestCaseDockerConfig,
    },
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use std::{thread::sleep, time::Duration};

struct CitreaDeposit;
#[async_trait]
impl TestCase for CitreaDeposit {
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
            with_batch_prover: false,
            with_sequencer: true,
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
            test_mode: false,
            bridge_initialize_params: BRIDGE_PARAMS.to_string(),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (sequencer, _full_node, _, da) = citrea::start_citrea(Self::sequencer_config(), f)
            .await
            .unwrap();

        let mut config = create_test_config_with_thread_name(None).await;
        citrea::update_config_with_citrea_e2e_values(&mut config, da, sequencer);

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
        // Mine blocks, so Citrea can fetch the block that contains the transaction.
        rpc.mine_blocks(101).await.unwrap();

        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc.client.get_block(&tx_info.blockhash.unwrap()).await?;
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height;

        while citrea::block_number(sequencer.client.http_client().clone()).await?
            <= block_height.try_into().unwrap()
        {
            println!("Waiting for block to be mined");
            rpc.mine_blocks(1).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        citrea::deposit(
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().unwrap(),
            tx,
        )
        .await?;

        sleep(Duration::from_secs(3));
        let balance =
            citrea::eth_get_balance(sequencer.client.http_client().clone(), EVMAddress([1; 20]))
                .await
                .unwrap();
        assert_eq!(
            balance,
            (config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER).into()
        );

        Ok(())
    }
}

#[tokio::test]
async fn citrea_deposit() -> Result<()> {
    TestCaseRunner::new(CitreaDeposit).run().await
}

struct CitreaFetchLCPAndDeposit;
#[async_trait]
impl TestCase for CitreaFetchLCPAndDeposit {
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
            // initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (sequencer, _full_node, lc_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();
        let lc_prover = lc_prover.unwrap();

        let mut config = create_test_config_with_thread_name(None).await;
        citrea::update_config_with_citrea_e2e_values(&mut config, da, sequencer);

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let citrea_client = CitreaClient::new(
            Url::parse(&config.citrea_rpc_url).unwrap(),
            Some(SECRET_KEYS[0].to_string()),
        )
        .unwrap();

        let (
            _verifiers,
            _operators,
            _aggregator,
            _watchtowers,
            _cleanup,
            _deposit_outpoint,
            move_txid,
        ) = run_single_deposit(&mut config, rpc.clone(), None).await?;

        // Mine blocks, so Citrea can fetch the block that contains the transaction.
        rpc.mine_blocks(101).await.unwrap();
        let height = rpc.client.get_block_count().await.unwrap() as u64;
        for _ in 0..height {
            sequencer.client.send_publish_batch_request().await?;
        }

        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc.client.get_block(&tx_info.blockhash.unwrap()).await?;
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height as u64;

        while citrea::block_number(sequencer.client.http_client().clone()).await?
            <= block_height.try_into().unwrap()
        {
            println!("Waiting for block to be mined");
            rpc.mine_blocks(1).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        citrea::deposit(
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().unwrap(),
            tx,
        )
        .await?;

        let height = rpc.client.get_block_count().await.unwrap() as u64;
        for _ in 0..height {
            sequencer.client.send_publish_batch_request().await?;
        }

        let balance =
            citrea::eth_get_balance(sequencer.client.http_client().clone(), EVMAddress([1; 20]))
                .await
                .unwrap();
        assert_eq!(
            balance,
            (config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER).into()
        );

        citrea_client.collect_events().await.unwrap();

        let lcp = lc_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(block_height)
            .await
            .unwrap();
        println!("lcp {:?}", lcp);

        Ok(())
    }
}

#[tokio::test]
async fn citrea_fetch_lcp_and_deposit() -> Result<()> {
    TestCaseRunner::new(CitreaFetchLCPAndDeposit).run().await
}
