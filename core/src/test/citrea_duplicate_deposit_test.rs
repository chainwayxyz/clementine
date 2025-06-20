use super::common::citrea::get_bridge_params;
use super::common::ActorsCleanup;
use crate::bitvm_client::SECP;
use crate::builder::transaction::input::UtxoVout;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::KickoffData;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::{TransactionRequest, WithdrawParams};
use crate::test::common::citrea::{get_citrea_safe_withdraw_params, SECRET_KEYS};
use crate::test::common::tx_utils::{
    create_tx_sender, ensure_outpoint_spent_while_waiting_for_light_client_sync,
    get_tx_from_signed_txs_with_type,
    get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync,
    mine_once_after_outpoint_spent_in_mempool,
};
use crate::test::common::{
    generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool, run_single_deposit,
};
use crate::utils::{FeePayingType, TxMetadata};
use crate::{
    builder::transaction::TransactionType,
    citrea::{CitreaClient, CitreaClientT, SATS_TO_WEI_MULTIPLIER},
};
use crate::{
    extended_rpc::ExtendedRpc,
    test::common::{
        citrea::{self},
        create_test_config_with_thread_name,
    },
};
use alloy::primitives::U256;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::SecretKey, Address, Amount};
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig};
use citrea_e2e::node::Node;
use citrea_e2e::{
    config::{BitcoinConfig, SequencerConfig, TestCaseConfig, TestCaseDockerConfig},
    framework::TestFramework,
    test_case::{TestCase, TestCaseRunner},
    Result,
};
use prost::Message;
use tonic::transport::Channel;
struct CitreaDuplicateDepositTest;

#[async_trait]
impl TestCase for CitreaDuplicateDepositTest {
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
                citrea: false,
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
        let (sequencer, _full_node, lc_prover, _batch_prover, da) =
            citrea::start_citrea(Self::sequencer_config(), f)
                .await
                .unwrap();

        let lc_prover = lc_prover.unwrap();

        let mut config = create_test_config_with_thread_name().await;

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

        rpc.mine_blocks(5).await.unwrap();

        let block_count = da.get_block_count().await?;
        tracing::info!("Block count before deposit: {:?}", block_count);

        tracing::info!(
            "Deposit starting at block height: {:?}",
            rpc.client.get_block_count().await?
        );
        let (
            verifiers,
            mut operators,
            aggregator,
            cleanup,
            deposit_params,
            move_txid,
            _deposit_blockhash,
            verifiers_public_keys,
        ) = run_single_deposit::<CitreaClient>(&mut config, rpc.clone(), None).await?;

        tracing::info!(
            "Deposit ending block_height: {:?}",
            rpc.client.get_block_count().await?
        );

        // Wait for TXs to be on-chain (CPFP etc.).
        rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        // Send deposit to Citrea
        let tx = rpc.client.get_raw_transaction(&move_txid, None).await?;
        let tx_info = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await?;
        let block = rpc.client.get_block(&tx_info.blockhash.unwrap()).await?;
        let block_height = rpc.client.get_block_info(&block.block_hash()).await?.height as u64;

        citrea::wait_until_lc_contract_updated(sequencer.client.http_client(), block_height)
            .await
            .unwrap();

        // Without a deposit, the balance should be 0.
        assert_eq!(
            citrea::eth_get_balance(
                sequencer.client.http_client().clone(),
                crate::EVMAddress([1; 20]),
            )
            .await
            .unwrap(),
            0
        );

        tracing::debug!("Depositing to Citrea...");

        for i in 0..2 {
            tracing::info!("Starting deposit no {}", i + 1);

            citrea::deposit(
                &rpc,
                sequencer.client.http_client().clone(),
                block.clone(),
                block_height.try_into().unwrap(),
                tx.clone(),
            )
            .await?;

            tracing::info!("Deposit no {} processed", i + 1);
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }

        Ok(())
    }
}

#[tokio::test]
async fn duplicate_deposit_test() -> Result<()> {
    TestCaseRunner::new(CitreaDuplicateDepositTest).run().await
}
