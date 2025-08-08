use super::common::citrea::get_bridge_params;
use crate::builder::transaction::input::UtxoVout;
use crate::citrea::{CitreaClient, CitreaClientT};
use crate::test::common::citrea::{CitreaE2EData, SECRET_KEYS};
use crate::test::common::clementine_utils::disprove_tests_common_setup;
use crate::test::common::tx_utils::get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync;
use crate::utils::initialize_logger;
use crate::{
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
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

pub enum DisproveTestVariant {
    HealthyState,
    CorruptedAssert,
}

struct DisproveTest {
    variant: DisproveTestVariant,
}

#[async_trait]
impl TestCase for DisproveTest {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-txindex=1",
                "-fallbackfee=0.000001",
                "-rpcallowip=0.0.0.0/0",
                "-limitancestorsize=1010",
                "-limitdescendantsize=1010",
                "-acceptnonstdtxn=1",
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
        // only verifiers 0 and 1 will send disprove transactions
        config.test_params.verifier_do_not_send_disprove_indexes = Some(vec![2, 3]);

        match self.variant {
            DisproveTestVariant::HealthyState => {}
            DisproveTestVariant::CorruptedAssert => {
                config.test_params.corrupted_asserts = true;
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

        let (actors, kickoff_txid, kickoff_tx) =
            disprove_tests_common_setup(&citrea_e2e_data).await;

        match self.variant {
            DisproveTestVariant::HealthyState => {
                let disprove_timeout_outpoint = OutPoint {
                    txid: kickoff_txid,
                    vout: UtxoVout::Disprove.get_vout(),
                };

                tracing::info!(
                    "Disprove timeout outpoint: {:?}, txid: {:?}",
                    disprove_timeout_outpoint,
                    kickoff_txid
                );

                let txid = get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync(
                    &rpc,
                    disprove_timeout_outpoint,
                    &actors,
                )
                .await
                .unwrap();

                tracing::info!("Disprove timeout txid: {:?}", txid);

                let kickoff_finalizer_out = OutPoint {
                    txid: kickoff_txid,
                    vout: UtxoVout::KickoffFinalizer.get_vout(),
                };

                let disprove_timeout_tx = rpc.get_raw_transaction(&txid, None).await?;

                assert!(
                    disprove_timeout_tx.input[1].previous_output == kickoff_finalizer_out,
                    "Disprove timeout tx input does not match kickoff finalizer outpoint. Disprove tx is sent instead."
                );

                tracing::info!("Disprove timeout transaction is onchain");
                Ok(())
            }
            DisproveTestVariant::CorruptedAssert => {
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

                tracing::info!("Disprove txid: {:?}", txid);

                let round_txid = kickoff_tx.input[0].previous_output.txid;

                let burn_connector = OutPoint {
                    txid: round_txid,
                    vout: UtxoVout::CollateralInRound.get_vout(),
                };

                let disprove_tx = rpc.get_raw_transaction(&txid, None).await?;

                assert!(
                    disprove_tx.input[1].previous_output == burn_connector,
                    "Disprove tx input does not match burn connector outpoint"
                );

                const CONTROL_BLOCK_LENGTH_DEPTH_11: usize = 1 + 32 + 32 * 11; // 385 - Length of the control block in the disprove script

                const CONTROL_BLOCK_LENGTH_DEPTH_10: usize = 1 + 32 + 32 * 10; // 353 - Length of the control block in the disprove script

                let witness = &disprove_tx.input[0].witness;
                let control_block = &witness[witness.len() - 1];

                // Check if the control block length matches either depth 10 or 11 which are the only valid depths for disprove transactions
                // This differs from additional disprove tx, which has a smaller control block length
                assert!(
                    control_block.len() == CONTROL_BLOCK_LENGTH_DEPTH_10
                        || control_block.len() == CONTROL_BLOCK_LENGTH_DEPTH_11,
                    "Control block length does not match expected depth 10 or 11 (got {})",
                    control_block.len()
                );

                tracing::info!("Disprove transaction is onchain");
                Ok(())
            }
        }
    }
}

/// Tests the disprove timeout mechanism in a healthy, non-disrupted protocol state.
///
/// # Arrange
/// * Sets up full Citrea stack with sequencer, DA node, batch prover, and light client prover.
/// * Uses default bridge configuration without any intentional disruption.
///
/// # Act
/// * Executes deposit and withdrawal flows.
/// * Processes the payout and kickoff transactions.
/// * Waits for the disprove timeout to activate.
///
/// # Assert
/// * Confirms that a disprove timeout transaction is created and included on Bitcoin.
/// * Verifies that the transaction correctly spends the `KickoffFinalizer` output.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn disprove_script_test_healthy() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let additional_disprove_test = DisproveTest {
        variant: DisproveTestVariant::HealthyState,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}

/// Tests the disprove mechanism in the presence of a corrupted assert commitment.
///
/// # Arrange
/// - Sets up the full Citrea stack: sequencer, DA node, batch prover, and light client prover.
/// - Sets `corrupted_asserts = true` in the configuration to simulate a corrupted assert scenario.
///
/// # Act
/// - Executes deposit and withdrawal flows.
/// - Processes payout and kickoff transactions.
/// - Waits for the disprove transaction to be triggered due to the corrupted assert.
///
/// # Assert
/// - Confirms a disprove transaction is created and included on Bitcoin.
/// - Validates that the disprove transaction consumes the correct input (the `BurnConnector` outpoint).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "This test is too slow, run separately"]
async fn disprove_script_test_corrupted_assert() -> Result<()> {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");
    std::env::set_var("CITREA_DOCKER_IMAGE", crate::test::CITREA_E2E_DOCKER_IMAGE);
    let additional_disprove_test = DisproveTest {
        variant: DisproveTestVariant::CorruptedAssert,
    };
    TestCaseRunner::new(additional_disprove_test).run().await
}
