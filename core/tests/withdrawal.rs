use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    bitcoin::DEFAULT_FINALITY_DEPTH,
    config::{TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

struct DockerIntegrationTest;
#[async_trait]
impl TestCase for DockerIntegrationTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: false,
            with_sequencer: true,
            with_full_node: false,
            docker: TestCaseDockerConfig {
                bitcoin: false,
                citrea: true,
            },
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let min_soft_confirmations_per_commitment =
            Self::sequencer_config().min_soft_confirmations_per_commitment;

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(1, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        full_node
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await?;

        let unspent_sequencer = sequencer
            .da
            .list_unspent(None, None, None, None, None)
            .await?;
        let unspent_da = da.list_unspent(None, None, None, None, None).await?;
        // Make sure sequencer.da and da don't hit the same wallet
        assert_ne!(unspent_sequencer, unspent_da);

        Ok(())
    }
}

#[tokio::test]
async fn test_docker_integration() -> Result<()> {
    TestCaseRunner::new(DockerIntegrationTest).run().await
}
