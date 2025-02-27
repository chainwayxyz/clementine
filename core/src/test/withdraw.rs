use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self, send_raw_transaction},
        create_test_config_with_thread_name, generate_withdrawal_transaction_and_signature,
        run_single_deposit,
    },
    utils::SECP,
    EVMAddress,
};
use alloy::signers::Signer;
use alloy::{
    consensus::TxEnvelope,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{self, address, U256},
    providers::{ext::AnvilApi, Provider},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy::{
    providers::{ProviderBuilder, WalletProvider},
    transports::http::reqwest::Url,
};
use async_trait::async_trait;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use std::{str::FromStr, thread::sleep, time::Duration};

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IWETH9,
    "src/test/common/citrea/Bridge.json"
);

struct CitreaDepositAndWithdraw;
#[async_trait]
impl TestCase for CitreaDepositAndWithdraw {
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
            // min_soft_confirmations_per_commitment: 50,
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
        citrea::update_config_with_citrea_e2e_da(&mut config, da);

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let citrea_url = format!(
            "http://{}:{}",
            sequencer.config.rollup.rpc.bind_host, sequencer.config.rollup.rpc.bind_port
        );
        config.citrea_rpc_url = citrea_url.clone();

        let evm_address = EVMAddress([
            0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce, 0x6a, 0xB8, 0x82, 0x72,
            0x79, 0xcf, 0xfF, 0xb9, 0x22, 0x66,
        ]);
        let (_verifiers, _operators, _aggregator, _watchtowers, _deposit_outpoint, move_txid) =
            run_single_deposit(&mut config, rpc.clone(), Some(evm_address)).await?;
        rpc.mine_blocks(1).await.unwrap();

        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc
            .client
            .get_block(&tx_info.blockhash.expect("Not None"))
            .await?;
        rpc.mine_blocks(101).await.unwrap();
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height;

        while citrea::block_number(sequencer.client.http_client().clone()).await?
            < block_height.try_into().unwrap()
        {
            tracing::debug!("Waiting for block to be mined");
            rpc.mine_blocks(1).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        citrea::deposit(
            sequencer.client.http_client().clone(),
            block,
            block_height.try_into().expect("Will not fail"),
            tx,
        )
        .await?;

        sleep(Duration::from_secs(3));
        let balance = citrea::eth_get_balance(sequencer.client.http_client().clone(), evm_address)
            .await
            .unwrap();
        // Has initial funds.
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
        let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<PrivateKeySigner>()
            .unwrap()
            .with_chain_id(Some(chain_id));
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(key))
            .on_http(Url::parse(&citrea_url).unwrap());

        let alice =
            primitives::Address::from_str("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        let bob =
            primitives::Address::from_str("70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();

        let tx = TransactionRequest::default()
            .with_from(alice)
            .with_to(bob)
            .with_nonce(0)
            .with_chain_id(chain_id)
            .with_value(U256::from(withdrawal_amount.to_sat()))
            .with_max_priority_fee_per_gas(10)
            .with_max_fee_per_gas(1000000001);
        let gas = provider.estimate_gas(&tx).await.unwrap();
        let req = tx.gas_limit(gas);

        send_raw_transaction(sequencer.client.http_client().clone(), req.clone())
            .await
            .unwrap();

        let call_set_value_req = provider.send_transaction(req).await.unwrap();
        let tx_hash = call_set_value_req
            .get_receipt()
            .await
            .unwrap()
            .transaction_hash;
        tracing::error!("asasd {:?}", tx_hash);

        Ok(())
    }
}

#[tokio::test]
async fn citrea_deposit_and_withdraw() -> Result<()> {
    TestCaseRunner::new(CitreaDepositAndWithdraw).run().await
}
