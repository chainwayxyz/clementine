use async_trait::async_trait;
use bitcoin::Network;
use citrea_e2e::{
    config::{TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use clementine_core::{
    config::BridgeConfig, database::Database, extended_rpc::ExtendedRpc, utils::initialize_logger,
};
use common::start_citrea;

mod common;

struct DepositOnCitrea;
#[async_trait]
impl TestCase for DepositOnCitrea {
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
        let (_sequencer, _full_node, da) = start_citrea(Self::sequencer_config(), f).await?;

        let mut config = create_test_config_with_thread_name!(None);
        config.bitcoin_rpc_password = da.config.rpc_password.clone();
        config.bitcoin_rpc_user = da.config.rpc_user.clone();
        config.bitcoin_rpc_password = da.config.rpc_password.clone();
        config.bitcoin_rpc_url = format!(
            "http://127.0.0.1:{}/wallet/{}",
            da.config.rpc_port,
            Network::Bitcoin // citrea-e2e internal.
        );

        let extended_rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;
        extended_rpc.mine_blocks(101).await?;

        Ok(())
    }
}

#[tokio::test]
async fn test_docker_integration() -> Result<()> {
    TestCaseRunner::new(DepositOnCitrea).run().await
}
