use super::common::citrea::get_bridge_params;
use crate::{citrea::CitreaClient, extended_rpc::ExtendedRpc, test::common::{
        citrea::{self}, create_test_config_with_thread_name, run_single_deposit}};
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
}
;
pub enum TestVariant {
    SingleDepositTest,
    DuplicateDepositTest
}

struct CitreaDepositTest{
    variant: TestVariant,
}

impl CitreaDepositTest {
    async fn duplicate_deposit_test(f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
        let (sequencer, _full_node, lc_prover, _batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();

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

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        rpc.mine_blocks(5).await.unwrap();

        let block_count = da.get_block_count().await?;
        tracing::info!("Block count before deposit: {:?}", block_count);

        tracing::info!(
            "Deposit starting at block height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (
            _,
            _,
            _,
            _,
            _,
            move_txid,
            _deposit_blockhash,
            _,
        ) = run_single_deposit::<CitreaClient>(&mut config, rpc.clone(), None, None).await?;

        tracing::info!(
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

        for i in 0..2 {
            tracing::info!("Starting deposit no {}", i + 1);

            citrea::deposit(
                &rpc,
                sequencer.client.http_client().clone(),
                block.clone(),
                block_height.try_into().unwrap(),
                tx.clone(),
            )
            .await?;

            tracing::info!("Deposit no {} processed", i + 1);
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        // sleep 1 second to ensure the deposit is processed
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

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

        Ok(())
    }

    async fn single_deposit_test(f: &mut TestFramework) -> Result<()> {
        tracing::info!("Starting Citrea");
                let (sequencer, _full_node, lc_prover, _batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();

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

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        rpc.mine_blocks(5).await.unwrap();

        let block_count = da.get_block_count().await?;
        tracing::info!("Block count before deposit: {:?}", block_count);

        tracing::info!(
            "Deposit starting at block height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (
            _,
            _,
            _,
            _,
            _,
            move_txid,
            _deposit_blockhash,
            _,
        ) = run_single_deposit::<CitreaClient>(&mut config, rpc.clone(), None, None).await?;

        tracing::info!(
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
            block.clone(),
            block_height.try_into().unwrap(),
            tx.clone(),
        )
        .await?;

        tracing::info!("Deposit done");

        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }


        // sleep 1 second to ensure the deposit is processed
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        
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

        Ok(())
    }
        
}

#[async_trait]
impl TestCase for CitreaDepositTest {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-txindex=1",
                "-fallbackfee=0.000001",
                "-rpcallowip=0.0.0.0/0",
                "-limitancestorsize=1010",
                "-limitdescendantsize=1010",
                "-acceptnonstdtxn=1",
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
                citrea: false,
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
            TestVariant::SingleDepositTest => Self::single_deposit_test(f).await,
            TestVariant::DuplicateDepositTest => {
                Self::duplicate_deposit_test(f).await
            }
        }
    }
}

#[tokio::test]
async fn duplicate_deposit_test() -> Result<()> {
    let test_case = CitreaDepositTest {
        variant: TestVariant::DuplicateDepositTest,
    };
    TestCaseRunner::new(test_case).run().await
}

#[tokio::test]
async fn single_deposit_test() -> Result<()> {
    let test_case = CitreaDepositTest {
        variant: TestVariant::SingleDepositTest,
    };
    TestCaseRunner::new(test_case).run().await
}
