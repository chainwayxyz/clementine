use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self, EVM_ADDRESSES, SECRET_KEYS},
        create_test_config_with_thread_name, generate_withdrawal_transaction_and_signature,
    },
    utils::SECP,
    EVMAddress,
};
use alloy::signers::Signer;
use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{self, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use alloy::{providers::ProviderBuilder, transports::http::reqwest::Url};
use async_trait::async_trait;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use std::str::FromStr;

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

        // EVM_ADDRESSES[0]
        let evm_address = EVMAddress([
            0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce, 0x6a, 0xB8, 0x82, 0x72,
            0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
        ]);

        let balance = citrea::eth_get_balance(sequencer.client.http_client().clone(), evm_address)
            .await
            .unwrap();
        // Wallet has initial funds and should be greater than the bridge amount
        // to start test.
        assert!(
            balance / 10_000_000_000 >= (config.protocol_paramset().bridge_amount.to_sat()).into()
        );

        let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let withdrawal_address = Address::p2tr(
            &SECP,
            user_sk.x_only_public_key(&SECP).0,
            None,
            config.protocol_paramset().network,
        );
        // We are giving enough sats to the user so that the operator can pay the
        // withdrawal and profit.
        let withdrawal_amount = Amount::from_sat(
            config.protocol_paramset().bridge_amount.to_sat()
                - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
        );
        let (withdrawal_tx, _withdrawal_tx_signature) =
            generate_withdrawal_transaction_and_signature(
                &config,
                &rpc,
                &withdrawal_address,
                withdrawal_amount,
            )
            .await;

        let chain_id: u64 = 5655;
        let key = SECRET_KEYS[0]
            .parse::<PrivateKeySigner>()
            .unwrap()
            .with_chain_id(Some(chain_id));
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(Url::parse(&config.citrea_rpc_url).unwrap());

        let alice = primitives::Address::from_str(EVM_ADDRESSES[0]).unwrap();
        let bob = primitives::Address::from_str(EVM_ADDRESSES[1]).unwrap();

        let nonce =
            citrea::eth_get_transaction_count(sequencer.client.http_client().clone(), evm_address)
                .await
                .unwrap();

        let tx_req = TransactionRequest::default()
            .with_from(alice)
            .with_to(bob)
            .with_nonce(nonce.try_into().unwrap())
            .with_chain_id(chain_id)
            .with_value(U256::from(withdrawal_amount.to_sat()))
            .with_max_priority_fee_per_gas(10)
            .with_max_fee_per_gas(1000000001);
        let gas = provider.estimate_gas(&tx_req).await.unwrap();
        let gas_price = provider.get_gas_price().await.unwrap();
        let tx_req = tx_req.gas_limit(gas);
        tracing::info!("Gas: {}, gas price: {}", gas, gas_price);

        let call_set_value_req = provider.send_transaction(tx_req).await.unwrap();
        let tx_hash = call_set_value_req
            .get_receipt()
            .await
            .unwrap()
            .transaction_hash;
        tracing::info!("EVM tx hash: {:?}", tx_hash);

        let balance_after =
            citrea::eth_get_balance(sequencer.client.http_client().clone(), evm_address)
                .await
                .unwrap();
        assert_ne!(balance, balance_after);

        assert_eq!(
            citrea::get_withdrawal_count(sequencer.client.http_client().clone())
                .await
                .unwrap(),
            0
        );

        let nonce =
            citrea::eth_get_transaction_count(sequencer.client.http_client().clone(), evm_address)
                .await
                .unwrap();
        citrea::withdraw(
            sequencer.client.http_client().clone(),
            EVM_ADDRESSES[0],
            *withdrawal_tx.get_txid(),
            0,
            withdrawal_amount.to_sat(),
            gas,
            gas_price,
            nonce,
        )
        .await
        .unwrap();

        Ok(())
    }
}

#[tokio::test]
async fn citrea_withdraw() -> Result<()> {
    TestCaseRunner::new(CitreaWithdraw).run().await
}
