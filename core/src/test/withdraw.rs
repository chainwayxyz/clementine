use super::common::citrea::BRIDGE_PARAMS;
use crate::test::common::citrea::{BRIDGE_CONTRACT_ADDRESS, SATS_TO_WEI_MULTIPLIER};
use crate::test::common::generate_withdrawal_transaction_and_signature;
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self, BRIDGE_CONTRACT, CITREA_CHAIN_ID, SECRET_KEYS},
        create_test_config_with_thread_name,
    },
    utils::SECP,
};
use alloy::primitives::FixedBytes;
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::{network::EthereumWallet, primitives::U256, signers::local::PrivateKeySigner};
use alloy::{providers::ProviderBuilder, transports::http::reqwest::Url};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};

struct CitreaWithdraw;
#[async_trait]
impl TestCase for CitreaWithdraw {
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

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            test_mode: false,
            bridge_initialize_params: BRIDGE_PARAMS.to_string(),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (sequencer, _full_node, da) = citrea::start_citrea(Self::sequencer_config(), f)
            .await
            .unwrap();

        let mut config = create_test_config_with_thread_name(None).await;
        citrea::update_config_with_citrea_e2e_values(&mut config, da, sequencer);

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let key = SECRET_KEYS[0]
            .parse::<PrivateKeySigner>()
            .unwrap()
            .with_chain_id(Some(CITREA_CHAIN_ID));
        let wallet_address = key.address();

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(Url::parse(&config.citrea_rpc_url).unwrap());
        let contract =
            BRIDGE_CONTRACT::new(BRIDGE_CONTRACT_ADDRESS.parse().unwrap(), provider.clone());

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

        let balance = provider.get_balance(wallet_address).await.unwrap();
        tracing::debug!("Balance: {}", balance);

        let citrea_withdrawal_tx = contract
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

        let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
        tracing::debug!("Citrea withdrawal tx receipt: {:?}", receipt);

        Ok(())
    }
}

#[tokio::test]
async fn citrea_withdraw() -> Result<()> {
    TestCaseRunner::new(CitreaWithdraw).run().await
}
