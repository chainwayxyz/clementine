use super::common::citrea::BRIDGE_PARAMS;
use crate::bitvm_client::SECP;
use crate::citrea::{CitreaClient, SATS_TO_WEI_MULTIPLIER};
use crate::test::common::citrea::SECRET_KEYS;
use crate::test::common::{generate_withdrawal_transaction_and_signature, run_single_deposit};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::FixedBytes;
use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::transports::http::reqwest::Url;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

struct CitreaDepositAndWithdrawE2E;
#[async_trait]
impl TestCase for CitreaDepositAndWithdrawE2E {
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
            bridge_initialize_params: BRIDGE_PARAMS.to_string(),
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
            initial_da_height: 200,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (sequencer, full_node, lc_prover, _, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();
        let lc_prover = lc_prover.unwrap();

        let mut config = create_test_config_with_thread_name(None).await;
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
        let (
            _verifiers,
            _operators,
            _aggregator,
            _watchtowers,
            _cleanup,
            _deposit_outpoint,
            _move_txid,
        ) = run_single_deposit(&mut config, rpc.clone(), None).await?;

        let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let withdrawal_address = Address::p2tr(
            &SECP,
            user_sk.x_only_public_key(&SECP).0,
            None,
            config.protocol_paramset().network,
        );
        let withdrawal_utxo = generate_withdrawal_transaction_and_signature(
            &config,
            &rpc,
            &withdrawal_address,
            Amount::from_sat(330),
        )
        .await
        .0
        .outpoint;
        println!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

        let citrea_client = CitreaClient::new(
            Url::parse(&config.citrea_rpc_url).unwrap(),
            Url::parse(&config.citrea_light_client_prover_url).unwrap(),
            Some(SECRET_KEYS[0].to_string().parse().unwrap()),
        )
        .unwrap();

        let citrea_withdrawal_tx = citrea_client
            .contract
            .withdraw(
                FixedBytes::from(withdrawal_utxo.txid.to_raw_hash().to_byte_array()),
                FixedBytes::from(withdrawal_utxo.vout.to_be_bytes()),
            )
            .value(U256::from(
                config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
            ))
            .send()
            .await
            .unwrap();
        // sequencer.client.send_publish_batch_request().await.unwrap();

        let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
        println!("Citrea withdrawal tx receipt: {:?}", receipt);

        // TODO: Send withdrawal signatures to operator.

        Ok(())
    }
}

#[tokio::test]
async fn citrea_deposit_and_withdraw_e2e() -> Result<()> {
    // TODO: temp hack to use the correct docker image
    std::env::set_var(
        "CITREA_DOCKER_IMAGE",
        "chainwayxyz/citrea-test:60d9fd633b9e62b647039f913c6f7f8c085ad42e",
    );
    TestCaseRunner::new(CitreaDepositAndWithdrawE2E).run().await
}
