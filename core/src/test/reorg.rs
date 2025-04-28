use super::common::citrea::get_bridge_params;
use crate::bitvm_client::SECP;
use crate::extended_rpc::ExtendedRpc;
use crate::test::common::{citrea, create_test_config_with_thread_name};
use bitcoin::key::Keypair;
use bitcoin::{Address, Amount, XOnlyPublicKey};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BitcoinConfig, SequencerConfig, TestCaseDockerConfig};
use citrea_e2e::test_case::TestCaseRunner;
use citrea_e2e::Result;
use citrea_e2e::{config::TestCaseConfig, framework::TestFramework, test_case::TestCase};
use std::time::Duration;
use tonic::async_trait;

struct BitcoinReorgTest;
#[async_trait]
impl TestCase for BitcoinReorgTest {
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
        let sequencer = f.sequencer.as_ref().expect("Sequencer is present");

        let das: Vec<_> = f.bitcoin_nodes.iter().collect();
        let da0 = das[0];
        let da1 = das[1];

        let mut config = create_test_config_with_thread_name().await;
        citrea::update_config_with_citrea_e2e_values(&mut config, da0, sequencer, None);

        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset().network);
        rpc.send_to_address(&address, Amount::from_sat(10000))
            .await
            .unwrap();

        // Disconnect nodes before
        f.bitcoin_nodes.disconnect_nodes().await?;

        // Wait for the sequencer commitments to hit the mempool
        da0.wait_mempool_len(1, None).await?;

        let mempool0 = da0.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 1);
        let mempool1 = da1.get_raw_mempool().await?;
        assert_eq!(mempool1.len(), 0);

        // Mine block with the sequencer commitment on the main chain
        da0.generate(1).await?;

        let original_chain_height = da0.get_block_count().await?;
        let original_chain_hash = da0.get_block_hash(original_chain_height).await?;
        let block = da0.get_block(&original_chain_hash).await?;
        assert_eq!(block.txdata.len(), 2); // Coinbase +

        // Buffer to wait for monitoring to update status to confirmed
        tokio::time::sleep(Duration::from_secs(2)).await;

        let da1_generated_blocks = 2;
        da1.generate(da1_generated_blocks).await?;

        // Reconnect nodes and wait for sync
        f.bitcoin_nodes.connect_nodes().await?;
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Assert that re-org occured
        let new_hash = da0.get_block_hash(original_chain_height).await?;
        assert_ne!(original_chain_hash, new_hash, "Re-org did not occur");

        let mempool0 = da0.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 1);

        // let pending_txs = sequencer
        //     .client
        //     .http_client()
        //     .da_get_pending_transactions()
        //     .await?;

        // assert!(mempool0.contains(&pending_txs[0].txid));
        // assert!(mempool0.contains(&pending_txs[1].txid));

        // let tx_status = sequencer
        //     .client
        //     .http_client()
        //     .da_get_tx_status(mempool0[0])
        //     .await?;
        // assert!(matches!(tx_status, Some(TxStatus::Pending { .. })));

        // Wait for re-org monitoring
        tokio::time::sleep(Duration::from_secs(20)).await;

        // Seq TXs should be rebroadcasted after re-org
        let mempool1 = da1.get_raw_mempool().await?;
        assert_eq!(mempool1.len(), 0);

        da1.generate(1).await?;
        let height = da0.get_block_count().await?;
        let hash = da0.get_block_hash(height).await?;
        let block = da0.get_block(&hash).await?;
        assert_eq!(block.txdata.len(), 1); // Coinbase

        da1.generate(DEFAULT_FINALITY_DEPTH - 1).await?;
        // let finalized_height = da1.get_finalized_height(None).await?;

        // batch_prover
        //     .wait_for_l1_height(finalized_height, None)
        //     .await?;

        // Generate on da1 and wait for da0 to be back in sync
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Verify that commitments are included
        // let original_commitments = batch_prover
        //     .client
        //     .http_client()
        //     .get_commitment_indices_by_l1(finalized_height)
        //     .await?
        //     .unwrap_or_default();

        // assert_eq!(original_commitments.len(), 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_bitcoin_reorg() -> Result<()> {
    TestCaseRunner::new(BitcoinReorgTest).run().await
}
