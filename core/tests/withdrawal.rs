use async_trait::async_trait;
use bitcoin::Network;
use citrea_e2e::{
    config::{BitcoinConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use clementine_core::{
    config::BridgeConfig, database::Database, extended_rpc::ExtendedRpc, operator::Operator,
    utils::initialize_logger,
};
use common::start_citrea;

mod common;

struct DepositOnCitrea;
#[async_trait]
impl TestCase for DepositOnCitrea {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-fallbackfee", "-fallbackfee=0.00001"],
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

        let _operator = Operator::new(config, rpc).await?;

        Ok(())
    }
}

#[tokio::test]
async fn test_docker_integration() -> Result<()> {
    TestCaseRunner::new(DepositOnCitrea).run().await
}
