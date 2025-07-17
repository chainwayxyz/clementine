use super::common::citrea::get_bridge_params;
use crate::builder::transaction::input::UtxoVout;
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::test::common::citrea::{CitreaE2EData, SECRET_KEYS};
use crate::test::common::tx_utils::get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync;
use crate::utils::initialize_logger;
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use async_trait::async_trait;
use bitcoin::OutPoint;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
pub enum TestVariant {
    CorruptedLatestBlockHash,
    CorruptedPayoutTxBlockHash,
    CorruptedChallengeSendingWatchtowers,
    OperatorForgotWatchtowerChallenge,
    CorruptedPublicInput,
}

struct AdditionalDisproveTest {
    variant: TestVariant,
}

#[async_trait]
impl TestCase for AdditionalDisproveTest {
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
            TestVariant::CorruptedLatestBlockHash => {
                config.test_params.disrupt_latest_block_hash_commit = true;
            }
            TestVariant::CorruptedPayoutTxBlockHash => {
                config.test_params.disrupt_payout_tx_block_hash_commit = true;
            }
            TestVariant::CorruptedChallengeSendingWatchtowers => {
                config
                    .test_params
                    .disrupt_challenge_sending_watchtowers_commit = true;
            }
            TestVariant::OperatorForgotWatchtowerChallenge => {
                config.test_params.operator_forgot_watchtower_challenge = true;
            }
            TestVariant::CorruptedPublicInput => {
                config.test_params.corrupted_public_input = true;
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

        let (actors, kickoff_txid, kickoff_tx) =
            citrea::disprove_tests_common_setup(&citrea_e2e_data).await;

        let disprove_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::Disprove.get_vout(),
        };

        tracing::info!(
            "Disprove outpoint: {:?}, txid: {:?}",
            disprove_outpoint,
            kickoff_txid
        );

        let txid = get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync(
            &rpc,
            disprove_outpoint,
            &actors,
        )
        .await
        .unwrap();

        tracing::info!("Additional disprove txid: {:?}", txid);

        let round_txid = kickoff_tx.input[0].previous_output.txid;

        let burn_connector = OutPoint {
            txid: round_txid,
            vout: UtxoVout::CollateralInRound.get_vout(),
        };

        let add_disprove_tx = rpc.client.get_raw_transaction(&txid, None).await?;

        assert!(
            add_disprove_tx.input[1].previous_output == burn_connector,
            "Additional disprove tx input does not match burn connector outpoint"
        );

        assert_eq!(
            add_disprove_tx.input[0].witness.len(),
            562,
            "Additional disprove tx input witness length is not 562"
        );

        tracing::info!("Additional disprove transaction is onchain");

        Ok(())
    }
}

/// Tests the disprove mechanism when the latest block hash commitment is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `disrupt_latest_block_hash_commit = true` to simulate a corrupted block hash during commitment.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted block hash in the commitment.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_disrupted_latest_block_hash() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedLatestBlockHash,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when the payout transaction's block hash commitment is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `disrupt_payout_tx_block_hash_commit = true` to simulate a corrupted block hash for the payout transaction during commitment.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted payout transaction block hash in the commitment.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_disrupted_payout_tx_block_hash() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedPayoutTxBlockHash,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when the commitment for challenges sent by watchtowers is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `disrupt_challenge_sending_watchtowers_commit = true` to simulate a corrupted commitment related to watchtower challenges.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted watchtower challenge commitment.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_disrupt_chal_sending_wts() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedChallengeSendingWatchtowers,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when an operator "forgets" to include a watchtower challenge.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `operator_forgot_watchtower_challenge = true` to simulate a scenario where an operator fails to send a necessary watchtower challenge.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the operator's failure to include a watchtower challenge.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_operator_forgot_wt_challenge() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::OperatorForgotWatchtowerChallenge,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism when the public input is intentionally corrupted.
///
/// # Arrange
/// * Sets up full Citrea infrastructure including sequencer, batch prover, light client prover, and DA node.
/// * Sets `corrupted_public_input = true` to simulate a corrupted public input scenario.
///
/// # Act
/// * Performs deposit and withdrawal operations between Bitcoin and Citrea.
/// * Processes payout and kickoff transactions.
/// * Waits for the disprove transaction to be triggered due to the corrupted public input.
///
/// # Assert
/// * Confirms that a disprove transaction is created on Bitcoin.
/// * Validates that the disprove transaction consumes the correct input (the burn connector outpoint).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn additional_disprove_script_test_corrupted_public_input() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:35ec72721c86c8e0cbc272f992eeadfcdc728102",
    );
    let additional_disprove_test = AdditionalDisproveTest {
        variant: TestVariant::CorruptedPublicInput,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}
