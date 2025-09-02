//! This module contains integration tests for generating data used in bridge circuit tests.
//!
//! The tests in this file are intended for data generation purposes only and are not meant to be run as part of the standard test suite.
//! They are ignored by default and should be executed manually when bridge-related code changes, to ensure that the generated test data remains up-to-date and consistent with the current implementation.
use super::common::citrea::get_bridge_params;
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::test::common::citrea::{CitreaE2EData, SECRET_KEYS};
use crate::test::common::clementine_utils::disprove_tests_common_setup;
use crate::utils::initialize_logger;
use crate::{
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
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
    WithAnnex,
    LargeInput,
    LargeOutput,
    LargeInputAndOutput,
    InsufficientTotalWork,
    Valid,
    FirstTwoValid,
    GenerateKickoffAndWtcTx,
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
            BridgeCircuitTestDataVariant::WithAnnex => {
                config.test_params.use_small_annex = true;
            }
            BridgeCircuitTestDataVariant::LargeInput => {
                config.test_params.use_large_annex = true;
            }
            BridgeCircuitTestDataVariant::LargeOutput => {
                config.test_params.use_large_output = true;
            }
            BridgeCircuitTestDataVariant::LargeInputAndOutput => {
                config.test_params.use_large_annex_and_output = true;
            }
            BridgeCircuitTestDataVariant::FirstTwoValid => {
                config
                    .test_params
                    .generate_varying_total_works_first_two_valid = true;
            }
            BridgeCircuitTestDataVariant::GenerateKickoffAndWtcTx => {
                config.test_params.generate_kickoff_and_wtc_txs = true;
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

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await?;

        let citrea_client = CitreaClient::new(
            config.citrea_rpc_url.clone(),
            config.citrea_light_client_prover_url.clone(),
            config.citrea_chain_id,
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
            config.citrea_request_timeout,
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
            disprove_tests_common_setup(&citrea_e2e_data).await;

        Ok(())
    }
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_generate_kickoff_and_wtc_tx() -> Result<()> {
    initialize_logger(None).expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::GenerateKickoffAndWtcTx,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_diverse_hcp_lengths() -> Result<()> {
    initialize_logger(None).expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::Valid,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_insuff_total_work_diverse_hcp_lens() -> Result<()> {
    initialize_logger(None).expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);

    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::InsufficientTotalWork,
    };
    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn bridge_circuit_test_data_diverse_hcp_lens_first_two_valid() -> Result<()> {
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);

    let bridge_circuit_test_data = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::FirstTwoValid,
    };

    TestCaseRunner::new(bridge_circuit_test_data).run().await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn challenge_tx_with_annex() -> Result<()> {
    initialize_logger(None).expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let watchtower_challenge_tx_variant = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::WithAnnex,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn challenge_tx_with_large_input() -> Result<()> {
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let watchtower_challenge_tx_variant = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::LargeInput,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn challenge_tx_with_large_output() -> Result<()> {
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let watchtower_challenge_tx_variant = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::LargeOutput,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}

#[tokio::test]
#[ignore = "Only run this test manually, it's for data generation purposes"]
async fn challenge_tx_with_both_large_input_and_output() -> Result<()> {
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let watchtower_challenge_tx_variant = BridgeCircuitTestData {
        variant: BridgeCircuitTestDataVariant::LargeInputAndOutput,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}
