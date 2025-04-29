use super::common::citrea::get_bridge_params;
use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::transaction::{BaseDepositData, DepositInfo, DepositType};
use crate::citrea::mock::MockCitreaClient;
use crate::citrea::CitreaClientT;
use crate::config::protocol::{ProtocolParamset, REGTEST_PARAMSET};
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::{Deposit, Empty};
use crate::test::common::citrea::get_transaction_params;
use crate::test::common::{
    citrea, create_actors, create_test_config_with_thread_name, get_deposit_address,
    mine_once_after_in_mempool,
};
use crate::EVMAddress;
use bitcoin::key::Keypair;
use bitcoin::{secp256k1::PublicKey, Address, Amount, XOnlyPublicKey};
use bitcoin::{OutPoint, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BitcoinConfig, SequencerConfig, TestCaseDockerConfig};
use citrea_e2e::test_case::TestCaseRunner;
use citrea_e2e::Result;
use citrea_e2e::{config::TestCaseConfig, framework::TestFramework, test_case::TestCase};
use eyre::Context;
use std::time::Duration;
use tonic::{async_trait, Request};

struct ReorgOnDeposit;
#[async_trait]
impl TestCase for ReorgOnDeposit {
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
            with_batch_prover: false,
            n_nodes: 2,
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

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let das: Vec<_> = f.bitcoin_nodes.iter().collect();
        let da0 = das[0];
        let da1 = das[1];

        let mut config = create_test_config_with_thread_name().await;
        const PARAMSET: ProtocolParamset = ProtocolParamset {
            finality_depth: DEFAULT_FINALITY_DEPTH as u32,
            ..REGTEST_PARAMSET
        };
        config.protocol_paramset = &PARAMSET;
        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da0,
            f.sequencer.as_ref().expect("Sequencer is present"),
            None,
        );

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        let (verifiers, operators, mut aggregator, _cleanup) =
            create_actors::<MockCitreaClient>(&mut config).await;

        let evm_address = EVMAddress([1u8; 20]);
        let actor = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );

        let verifiers_public_keys: Vec<PublicKey> = aggregator
            .setup(Request::new(Empty {}))
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();

        let (deposit_address, _) =
            get_deposit_address(&config, evm_address, verifiers_public_keys.clone()).unwrap();
        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await
            .unwrap();

        mine_once_after_in_mempool(&rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None)
            .await?;

        // Reorg will happen before the deposit tx.
        f.bitcoin_nodes.disconnect_nodes().await?;

        let deposit_info = DepositInfo {
            deposit_outpoint,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: actor.address.as_unchecked().to_owned(),
            }),
        };
        let deposit: Deposit = deposit_info.clone().into();

        let move_txid: Txid = aggregator
            .new_deposit(deposit)
            .await?
            .into_inner()
            .try_into()?;

        // Wait till tx_sender can send the fee_payer_tx to the mempool and then mine it
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // da0.wait_mempool_len(1, None).await?;
        da0.generate(1).await.unwrap();

        mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), None).await?;

        let og_transaction = rpc
            .client
            .get_raw_transaction(&move_txid, None)
            .await
            .unwrap();
        let og_tx_info: bitcoincore_rpc::json::GetRawTransactionResult = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await
            .unwrap();
        assert!(og_tx_info.blockhash.is_some());
        let og_block: bitcoincore_rpc::json::GetBlockResult = rpc
            .client
            .get_block_info(&og_tx_info.blockhash.unwrap())
            .await
            .unwrap();

        // Make the second branch longer.
        da1.generate(3).await.unwrap();

        // Reconnect nodes and wait for sync
        f.bitcoin_nodes.connect_nodes().await?;
        f.bitcoin_nodes.wait_for_sync(None).await?;

        assert!(rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await
            .unwrap()
            .blockhash
            .is_none());

        // Wait till tx_sender can send the fee_payer_tx to the mempool and then mine it
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // da0.wait_mempool_len(1, None).await?;
        da1.generate(1).await.unwrap();

        mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), None)
            .await
            .unwrap();
        let og_tx_info: bitcoincore_rpc::json::GetRawTransactionResult = rpc
            .client
            .get_raw_transaction_info(&move_txid, None)
            .await
            .unwrap();
        assert!(og_tx_info.blockhash.is_some());

        // let block_height = block.height;
        // let block = rpc
        //     .client
        //     .get_block(&tx_info.blockhash.unwrap())
        //     .await
        //     .unwrap();
        // let transaction_params =
        //     get_transaction_params(transaction.clone(), block, block_height as u32, move_txid);

        // ------------------------------------
        // ------------------------------------
        // ------------------------------------

        // // Disconnect nodes before
        // f.bitcoin_nodes.disconnect_nodes().await?;

        // // Wait for the sequencer commitments to hit the mempool
        // da0.wait_mempool_len(1, None).await?;

        // let mempool0 = da0.get_raw_mempool().await?;
        // assert_eq!(mempool0.len(), 1);
        // let mempool1 = da1.get_raw_mempool().await?;
        // assert_eq!(mempool1.len(), 0);

        // // Mine block with the sequencer commitment on the main chain
        // da0.generate(1).await?;

        // let original_chain_height = da0.get_block_count().await?;
        // let original_chain_hash = da0.get_block_hash(original_chain_height).await?;
        // let block = da0.get_block(&original_chain_hash).await?;
        // assert_eq!(block.txdata.len(), 2); // Coinbase +

        // // Buffer to wait for monitoring to update status to confirmed
        // tokio::time::sleep(Duration::from_secs(2)).await;

        // let da1_generated_blocks = 2;
        // da1.generate(da1_generated_blocks).await?;

        // // Reconnect nodes and wait for sync
        // f.bitcoin_nodes.connect_nodes().await?;
        // f.bitcoin_nodes.wait_for_sync(None).await?;

        // // Assert that re-org occured
        // let new_hash = da0.get_block_hash(original_chain_height).await?;
        // assert_ne!(original_chain_hash, new_hash, "Re-org did not occur");

        // let mempool0 = da0.get_raw_mempool().await?;
        // assert_eq!(mempool0.len(), 1);

        // // Wait for re-org monitoring
        // tokio::time::sleep(Duration::from_secs(20)).await;

        // // Seq TXs should be rebroadcasted after re-org
        // let mempool1 = da1.get_raw_mempool().await?;
        // assert_eq!(mempool1.len(), 0);

        // da1.generate(1).await?;
        // let height = da0.get_block_count().await?;
        // let hash = da0.get_block_hash(height).await?;
        // let block = da0.get_block(&hash).await?;
        // assert_eq!(block.txdata.len(), 1); // Coinbase

        // da1.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        // // Generate on da1 and wait for da0 to be back in sync
        // f.bitcoin_nodes.wait_for_sync(None).await?;

        Ok(())
    }
}

#[tokio::test]
async fn reorg_on_deposit() -> Result<()> {
    TestCaseRunner::new(ReorgOnDeposit).run().await
}
