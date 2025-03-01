use crate::test::common::citrea::SATS_TO_WEI_MULTIPLIER;
use crate::test::withdraw::primitives::address;
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
use alloy::{
    network::EthereumWallet,
    primitives::{self, U256},
    signers::local::PrivateKeySigner,
};
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
            bridge_initialize_params: "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000002d4a20423a0b35060e62053765e2aba342f1c242e78d68f5248aca26e703c0c84ca322ac0063066369747265611400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a08000000003b9aca006800000000000000000000000000000000000000000000".to_string(),
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

        // Create the wallet first
        let key = SECRET_KEYS[0]
            .parse::<PrivateKeySigner>()
            .unwrap()
            .with_chain_id(Some(CITREA_CHAIN_ID));

        // Get the address from the wallet's signer
        let wallet_address = key.address();

        let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let withdrawal_address = Address::p2tr(
            &SECP,
            user_sk.x_only_public_key(&SECP).0,
            None,
            config.protocol_paramset().network,
        );

        let withdrawal_utxo = rpc
            .send_to_address(&withdrawal_address, Amount::from_sat(330))
            .await
            .unwrap();

        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(Url::parse(&config.citrea_rpc_url).unwrap());

        let balance = provider.get_balance(wallet_address).await.unwrap();
        println!("Balance: {}", balance);

        let contract = BRIDGE_CONTRACT::new(
            address!("3100000000000000000000000000000000000002"),
            provider,
        );

        let x = contract
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

        let receipt = x.get_receipt().await.unwrap();
        println!("Withdrawal: {:?}", receipt);

        Ok(())
    }
}

#[tokio::test]
async fn citrea_withdraw() -> Result<()> {
    TestCaseRunner::new(CitreaWithdraw).run().await
}
