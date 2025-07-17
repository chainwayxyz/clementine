use super::common::citrea::get_bridge_params;
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::test::common::citrea::{CitreaE2EData, SECRET_KEYS};
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

pub enum ChallengeTxTestVariant {
    WithAnnex,
    LargeInput,
    LargeOutput,
    LargeInputAndOutput,
}

struct WatchtowerChallengeTxTest {
    variant: ChallengeTxTestVariant,
}

#[async_trait]
impl TestCase for WatchtowerChallengeTxTest {
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

        // Set the correct flag based on variant
        match self.variant {
            ChallengeTxTestVariant::WithAnnex => {
                config.test_params.use_small_annex = true;
            }
            ChallengeTxTestVariant::LargeInput => {
                config.test_params.use_large_annex = true;
            }
            ChallengeTxTestVariant::LargeOutput => {
                config.test_params.use_large_output = true;
            }
            ChallengeTxTestVariant::LargeInputAndOutput => {
                config.test_params.use_large_annex_and_output = true;
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
#[ignore = "This test is too slow, run separately"]
async fn challenge_tx_with_annex() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let watchtower_challenge_tx_variant = WatchtowerChallengeTxTest {
        variant: ChallengeTxTestVariant::WithAnnex,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}

#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn challenge_tx_with_large_input() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let watchtower_challenge_tx_variant = WatchtowerChallengeTxTest {
        variant: ChallengeTxTestVariant::LargeInput,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}

#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn challenge_tx_with_large_output() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let watchtower_challenge_tx_variant = WatchtowerChallengeTxTest {
        variant: ChallengeTxTestVariant::LargeOutput,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}

#[tokio::test]
#[ignore = "This test is too slow, run separately"]
async fn challenge_tx_with_large_input_and_output() -> Result<()> {
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let watchtower_challenge_tx_variant = WatchtowerChallengeTxTest {
        variant: ChallengeTxTestVariant::LargeInputAndOutput,
    };
    TestCaseRunner::new(watchtower_challenge_tx_variant)
        .run()
        .await
}
