//! This module contains integration tests for generating data used in bridge circuit tests.
//!
//! The tests in this file are intended for data generation purposes only and are not meant to be run as part of the standard test suite.
//! They are ignored by default and should be executed manually when bridge-related code changes, to ensure that the generated test data remains up-to-date and consistent with the current implementation.
use super::common::citrea::get_bridge_params;
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::test::common::citrea::{CitreaE2EData, SECRET_KEYS};
use crate::utils::initialize_logger;
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use async_trait::async_trait;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

#[derive(PartialEq)]
pub enum BridgeCircuitTestDataVariant {
    InsufficientTotalWork,
    Valid,
    FirstTwoValid,
}

struct BridgeCircuitTestData {
    variant: BridgeCircuitTestDataVariant,
}

#[async_trait]
impl TestCase for BridgeCircuitTestData {
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
        tracing::info!("Starting Citrea");
        let (sequencer, full_node, lc_prover, batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();
        let batch_prover = batch_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;

        match self.variant {
            BridgeCircuitTestDataVariant::InsufficientTotalWork => {
                config
                    .test_params
                    .generate_varying_total_works_insufficient_total_work = true;
            }
            BridgeCircuitTestDataVariant::Valid => {
                config.test_params.generate_varying_total_works = true;
            }
            BridgeCircuitTestDataVariant::FirstTwoValid => {
                config
                    .test_params
                    .generate_varying_total_works_first_two_valid = true;
            }
        }

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

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .await
        .unwrap();

        let citrea_e2e_data = CitreaE2EData {
            sequencer,
            full_node,
            lc_prover,
            batch_prover,
            da,
            config: config.clone(),
            citrea_client: &citrea_client,
            rpc: &rpc,
        };

        let (_actors, _kickoff_txid, _kickoff_tx) =
            citrea::disprove_tests_common_setup(&citrea_e2e_data).await;

        Ok(())
    }
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_diverse_hcp_lengths() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::Valid,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_insuff_total_work_diverse_hcp_lens() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );

    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::InsufficientTotalWork,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_diverse_hcp_lens_first_two_valid() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );

    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::FirstTwoValid,
    };

    TestCaseRunner::new(bridge_circuit_test_data).run().await
}
