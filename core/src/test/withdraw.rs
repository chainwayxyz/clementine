use super::common::citrea::BRIDGE_PARAMS;
use crate::citrea::{
    BRIDGE_CONTRACT, BRIDGE_CONTRACT_ADDRESS, CITREA_CHAIN_ID, SATS_TO_WEI_MULTIPLIER,
};
use crate::test::common::generate_withdrawal_transaction_and_signature;
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self, SECRET_KEYS},
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

struct CitreaWithdrawAndGetUTXO;
#[async_trait]
impl TestCase for CitreaWithdrawAndGetUTXO {
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
        println!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

        let balance = provider.get_balance(wallet_address).await.unwrap();
        println!("Balance: {}", balance);

        let withdrawal_count = contract.getWithdrawalCount().call().await.unwrap();
        assert_eq!(withdrawal_count._0, U256::from(0));

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
        println!("Citrea withdrawal tx receipt: {:?}", receipt);

        let withdrawal_count = contract.getWithdrawalCount().call().await.unwrap();
        assert_eq!(withdrawal_count._0, U256::from(1));

        let citrea_withdrawal_utxo = crate::citrea::withdrawal_utxos(provider, 0).await.unwrap();
        println!("Citrea withdrawal UTXO: {:?}", citrea_withdrawal_utxo);

        assert_eq!(citrea_withdrawal_utxo, withdrawal_utxo);

        Ok(())
    }
}

#[tokio::test]
async fn citrea_withdraw_and_get_utxo() -> Result<()> {
    TestCaseRunner::new(CitreaWithdrawAndGetUTXO).run().await
}
