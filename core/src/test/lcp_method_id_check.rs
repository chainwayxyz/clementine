use crate::citrea::{CitreaClient, CitreaClientT};
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::test::common::citrea::SECRET_KEYS;
use crate::test::common::create_test_config_with_thread_name;
use crate::utils::initialize_logger;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::LightClientProverConfig;
use citrea_e2e::node::NodeKind;
use citrea_e2e::{
    config::{BitcoinConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
};
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const INITIAL_DA_HEIGHT: u64 = 60;

struct CitreaLcpProverE2E;

#[async_trait]
impl TestCase for CitreaLcpProverE2E {
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
            with_sequencer: false,
            with_batch_prover: false,
            with_light_client_prover: true,
            with_full_node: false,
            n_nodes: HashMap::from([(NodeKind::Bitcoin, 1)]),
            docker: TestCaseDockerConfig {
                bitcoin: true,
                citrea: true,
            },
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: INITIAL_DA_HEIGHT,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(INITIAL_DA_HEIGHT)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> citrea_e2e::Result<()> {
        let lc_prover = f
            .light_client_prover
            .as_ref()
            .expect("Light client prover is present");
        let da = f.bitcoin_nodes.get(0).expect("There is a bitcoin node");

        let mut config = create_test_config_with_thread_name().await;
        config.bitcoin_rpc_user = da.config.rpc_user.clone().into();
        config.bitcoin_rpc_password = da.config.rpc_password.clone().into();
        config.bitcoin_rpc_url = format!(
            "http://127.0.0.1:{}/wallet/{}",
            da.config.rpc_port,
            NodeKind::Bitcoin
        );
        config.citrea_rpc_url = "http://127.0.0.1:0".to_string();
        config.citrea_light_client_prover_url = format!(
            "http://{}:{}",
            lc_prover.config.rollup.rpc.bind_host, lc_prover.config.rollup.rpc.bind_port
        );

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await?;

        let target_l1_height = INITIAL_DA_HEIGHT;
        lc_prover
            .wait_for_l1_height(target_l1_height, Some(Duration::from_secs(120)))
            .await?;

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
            config.citrea_request_timeout,
        )
        .await?;

        let (_, receipt, _) = poll_lcp(&citrea_client, target_l1_height, &config).await?;
        let proof_output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes)?;

        assert_eq!(
            proof_output.latest_da_state.block_hash,
            rpc.get_block_hash(target_l1_height).await?.to_byte_array()
        );
        let expected_method_id = config.protocol_paramset().get_lcp_image_id()?;
        let actual_method_id = lcp_method_id(&proof_output);
        assert_eq!(
            actual_method_id,
            expected_method_id,
            "LCP method ID does not match paramset method ID: expected {}, got {}",
            hex::encode(expected_method_id),
            hex::encode(actual_method_id)
        );

        if let Ok(path) = std::env::var("CLEMENTINE_REGTEST_LCP_RECEIPT_OUT") {
            std::fs::write(&path, borsh::to_vec(&receipt)?)?;
            println!("Wrote regtest LCP receipt fixture to {path}");
        }

        Ok(())
    }
}

fn lcp_method_id(proof_output: &LightClientCircuitOutput) -> [u8; 32] {
    proof_output
        .light_client_proof_method_id
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Conversion from [u32; 8] to [u8; 32] cannot fail")
}

async fn poll_lcp(
    citrea_client: &CitreaClient,
    l1_height: u64,
    config: &crate::config::BridgeConfig,
) -> citrea_e2e::Result<(
    circuits_lib::bridge_circuit::structs::LightClientProof,
    risc0_zkvm::Receipt,
    u64,
)> {
    let start = Instant::now();
    let timeout = Duration::from_secs(120);

    loop {
        if let Some(proof) = citrea_client
            .get_light_client_proof(l1_height, config.protocol_paramset())
            .await?
        {
            return Ok(proof);
        }

        if start.elapsed() > timeout {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Timed out waiting for LCP at L1 height {l1_height}"),
            )
            .into());
        }

        sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn citrea_lcp_prover_returns_expected_method_id() -> citrea_e2e::Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    TestCaseRunner::new(CitreaLcpProverE2E).run().await
}
