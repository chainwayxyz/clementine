use async_trait::async_trait;
use bitcoin::Network;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    config::{BitcoinConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use clementine_core::{
    config::BridgeConfig, database::Database, extended_rpc::ExtendedRpc, utils::initialize_logger,
};
use common::{run_single_deposit, start_citrea};

mod common;

struct DepositOnCitrea;
#[async_trait]
impl TestCase for DepositOnCitrea {
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

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (_sequencer, full_node, da) = start_citrea(Self::sequencer_config(), f).await?;

        let mut config = create_test_config_with_thread_name!(None);
        config.bitcoin_rpc_password = da.config.rpc_password.clone();
        config.bitcoin_rpc_user = da.config.rpc_user.clone();
        config.bitcoin_rpc_password = da.config.rpc_password.clone();
        config.bitcoin_rpc_url = format!(
            "http://127.0.0.1:{}/wallet/{}",
            da.config.rpc_port,
            Network::Bitcoin // citrea-e2e internal.
        );

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;
        rpc.mine_blocks(101).await?; // TODO: remove; only for checking network availability

        let citrea_url = format!(
            "http://{}:{}",
            full_node.config.rollup.rpc.bind_host, full_node.config.rollup.rpc.bind_port
        );
        config.citrea_rpc_url = citrea_url;

        let (_verifiers, _operators, _aggregator, _watchtowers, _deposit_outpoint, move_txid) =
            run_single_deposit(&mut config, rpc.clone()).await?;

        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        tracing::info!("Move tx: {:?}", tx);

        Ok(())
    }
}

#[tokio::test]
async fn test_docker_integration() -> Result<()> {
    TestCaseRunner::new(DepositOnCitrea).run().await
}
