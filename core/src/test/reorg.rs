//! # Reorg Tests
//!
//! This module contains tests that check the behavior of the some components
//! in the event of a reorg.

use crate::actor::Actor;
use crate::bitcoin_syncer::BitcoinSyncer;
use crate::config::protocol::{ProtocolParamset, REGTEST_PARAMSET};
use crate::database::Database;
use crate::deposit::{BaseDepositData, DepositInfo, DepositType};
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::rpc::clementine::{Deposit, Empty, SendMoveTxRequest};
use crate::task::{IntoTask, TaskExt};
use crate::test::common::citrea::MockCitreaClient;
use crate::test::common::tx_utils::create_bumpable_tx;
use crate::test::common::{
    citrea, create_actors, create_test_config_with_thread_name, get_deposit_address,
    mine_once_after_in_mempool,
};
use crate::tx_sender::TxSender;
use crate::utils::FeePayingType;
use crate::{rpc, EVMAddress};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Txid;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BitcoinConfig, TestCaseDockerConfig};
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::TestCaseRunner;
use citrea_e2e::Result;
use citrea_e2e::{config::TestCaseConfig, framework::TestFramework, test_case::TestCase};
use std::collections::HashMap;
use std::time::Duration;
use tonic::{async_trait, Request};

struct TxSenderReorgBehavior;
#[async_trait]
impl TestCase for TxSenderReorgBehavior {
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
            n_nodes: HashMap::from([(NodeKind::Bitcoin, 2)]),
            docker: TestCaseDockerConfig {
                bitcoin: true,
                citrea: true,
            },
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (da0, da1) = (
            f.bitcoin_nodes.get(0).unwrap(),
            f.bitcoin_nodes.get(1).unwrap(),
        );

        let mut config = create_test_config_with_thread_name().await;
        const PARAMSET: ProtocolParamset = ProtocolParamset {
            finality_depth: DEFAULT_FINALITY_DEPTH as u32,
            start_height: 0,
            ..REGTEST_PARAMSET
        };
        config.protocol_paramset = &PARAMSET;
        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da0,
            f.sequencer.as_ref().expect("Sequencer is present"),
            None,
        );

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await
        .unwrap();

        let actor = Actor::new(config.secret_key, config.protocol_paramset.network);
        let db = Database::new(&config).await.unwrap();

        let btc_syncer = BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset())
            .await
            .unwrap()
            .into_task()
            .cancelable_loop();
        btc_syncer.0.into_bg();

        let tx_sender = TxSender::new(
            actor.clone(),
            rpc.clone(),
            db.clone(),
            "tx_sender".into(),
            config.clone(),
        );
        let tx_sender_client = tx_sender.client();
        let tx_sender = tx_sender.into_task().cancelable_loop();
        tx_sender.0.into_bg();

        let tx = create_bumpable_tx(
            &rpc,
            &actor,
            config.protocol_paramset.network,
            FeePayingType::CPFP,
            false,
        )
        .await
        .unwrap();
        let txid = tx.compute_txid();

        // Reorg will happen before the deposit tx.
        f.bitcoin_nodes.disconnect_nodes().await?;

        let mut dbtx = db.begin_transaction().await.unwrap();
        let id = tx_sender_client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::CPFP,
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        dbtx.commit().await.unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;
        rpc.mine_blocks(1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        rpc.mine_blocks(1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        mine_once_after_in_mempool(&rpc, txid, Some("bumpable_cpfp_tx"), None).await?;

        assert!(rpc
            .get_raw_transaction_info(&txid, None)
            .await
            .unwrap()
            .blockhash
            .is_some());

        let tx_debug = tx_sender_client.debug_tx(id).await.unwrap();
        tracing::debug!("debug tx: {:?}", tx_debug);
        let fee_payer = Txid::from_slice(
            &<std::option::Option<rpc::clementine::Txid> as Clone>::clone(
                &tx_debug.fee_payer_utxos[0].txid,
            )
            .unwrap()
            .txid,
        )
        .unwrap();
        assert!(rpc
            .get_raw_transaction_info(&fee_payer, None)
            .await
            .unwrap()
            .blockhash
            .is_some());

        let before_reorg_tip_height: u64 = da0.get_block_count().await?;
        let before_reorg_tip_hash = da0.get_best_block_hash().await?;

        tracing::info!(
            "da0 height: {}, da1 height: {}",
            da0.get_block_count().await?,
            da1.get_block_count().await?,
        );

        let block_diff = da0.get_block_count().await? - da1.get_block_count().await?;

        assert!(
            block_diff <= DEFAULT_FINALITY_DEPTH,
            "difference between da0 and da1 is too large: {block_diff}",
        );

        // Make the second branch longer and perform a reorg.
        da1.generate(block_diff + 1).await.unwrap();
        f.bitcoin_nodes.connect_nodes().await?;
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Check that reorg happened.
        let current_tip_height = rpc.get_block_count().await?;
        assert_eq!(
            before_reorg_tip_height + 1,
            current_tip_height,
            "Re-org did not occur"
        );
        let current_tip_hash = rpc.get_block_hash(current_tip_height).await?;
        assert_ne!(
            before_reorg_tip_hash, current_tip_hash,
            "Re-org did not occur"
        );

        assert!(rpc
            .get_raw_transaction_info(&txid, None)
            .await
            .unwrap()
            .blockhash
            .is_none());

        let tx_debug = tx_sender_client.debug_tx(id).await.unwrap();
        tracing::info!(
            "debug tx: {:?}",
            tx_sender_client.debug_tx(id).await.unwrap()
        );
        let fee_payer = Txid::from_slice(
            &<std::option::Option<rpc::clementine::Txid> as Clone>::clone(
                &tx_debug.fee_payer_utxos[0].txid,
            )
            .unwrap()
            .txid,
        )
        .unwrap();
        tracing::info!(
            "fee_payer: {:?}",
            rpc.get_mempool_entry(&fee_payer).await.unwrap()
        );
        tracing::info!("fee payer txid: {:?}, main txid: {:?}", fee_payer, txid);

        tracing::info!(
            "Main cpfp mempool entry: {:?}",
            rpc.get_mempool_entry(&txid).await
        );

        assert!(rpc
            .get_raw_transaction_info(&fee_payer, None)
            .await
            .unwrap()
            .blockhash
            .is_none());

        rpc.mine_blocks(1).await.unwrap();

        assert!(rpc
            .get_raw_transaction_info(&fee_payer, None)
            .await
            .unwrap()
            .blockhash
            .is_some());

        // with bitcoin v30, the feepayer + cpfp 1p1c package can both be in the mempool together
        // so they will get mined together in the same block
        assert!(rpc
            .get_raw_transaction_info(&txid, None)
            .await
            .unwrap()
            .blockhash
            .is_some(),);

        Ok(())
    }
}

#[tokio::test]
async fn reorg_on_cpfp_tx() -> Result<()> {
    TestCaseRunner::new(TxSenderReorgBehavior).run().await
}

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
            n_nodes: HashMap::from([(NodeKind::Bitcoin, 2)]),
            docker: TestCaseDockerConfig {
                bitcoin: true,
                citrea: true,
            },
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (da0, da1) = (
            f.bitcoin_nodes.get(0).unwrap(),
            f.bitcoin_nodes.get(1).unwrap(),
        );

        let mut config = create_test_config_with_thread_name().await;
        const PARAMSET: ProtocolParamset = ProtocolParamset {
            finality_depth: DEFAULT_FINALITY_DEPTH as u32,
            start_height: 0,
            ..REGTEST_PARAMSET
        };
        config.protocol_paramset = &PARAMSET;
        citrea::update_config_with_citrea_e2e_values(
            &mut config,
            da0,
            f.sequencer.as_ref().expect("Sequencer is present"),
            None,
        );

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await
        .unwrap();

        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();

        let evm_address = EVMAddress([1u8; 20]);
        let actor = Actor::new(config.secret_key, config.protocol_paramset().network);

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

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
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

        let move_tx = aggregator
            .new_deposit(deposit)
            .await
            .expect("Failed to make a request")
            .into_inner();

        let move_txid: Txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint.into()),
                raw_tx: Some(move_tx),
            })
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();

        // let move_txid: Transaction = aggregator.new_deposit(deposit).await?.into_inner();

        // Wait till tx_sender can send the fee_payer_tx to the mempool and then mine it
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        rpc.mine_blocks(1).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), None).await?;

        // Move tx is on-chain.
        assert!(rpc
            .get_raw_transaction_info(&move_txid, None)
            .await
            .unwrap()
            .blockhash
            .is_some());
        let before_reorg_tip_height: u64 = da0.get_block_count().await?;
        let before_reorg_tip_hash = da0.get_best_block_hash().await?;

        tracing::info!(
            "da0 height: {}, da1 height: {}",
            da0.get_block_count().await?,
            da1.get_block_count().await?,
        );

        let block_diff = da0.get_block_count().await? - da1.get_block_count().await?;

        assert!(
            block_diff <= DEFAULT_FINALITY_DEPTH,
            "difference between da0 and da1 is too large: {block_diff}",
        );

        // Make the second branch longer and perform a reorg.
        da1.generate(block_diff + 1).await.unwrap();

        tracing::info!(
            "da0 height: {}, da1 height: {}",
            da0.get_block_count().await?,
            da1.get_block_count().await?,
        );

        f.bitcoin_nodes.connect_nodes().await?;
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Check that reorg happened.
        let current_tip_height = rpc.get_block_count().await?;
        assert_eq!(
            before_reorg_tip_height + 1,
            current_tip_height,
            "Re-org did not occur"
        );
        let current_tip_hash = rpc.get_block_hash(current_tip_height).await?;
        assert_ne!(
            before_reorg_tip_hash, current_tip_hash,
            "Re-org did not occur"
        );

        assert!(rpc
            .get_raw_transaction_info(&move_txid, None)
            .await
            .unwrap()
            .blockhash
            .is_none());

        // First mine once for fee payer tx of move tx + deposit tx to be included in chain
        rpc.mine_blocks(1).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // now mine again for move tx to be included in chain
        rpc.mine_blocks(1).await.unwrap();

        // Move tx should be on-chain.
        assert!(rpc
            .get_raw_transaction_info(&move_txid, None)
            .await
            .unwrap()
            .blockhash
            .is_some());

        Ok(())
    }
}

#[tokio::test]
async fn reorg_on_deposit() -> Result<()> {
    TestCaseRunner::new(ReorgOnDeposit).run().await
}
