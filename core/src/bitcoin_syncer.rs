use std::time::Duration;

use bitcoin::{block::Header, BlockHash, Transaction};
use bitcoincore_rpc::RpcApi;
use futures::future::try_join_all;
use tokio::{sync::broadcast, task::JoinHandle, time::sleep};

use crate::{database::Database, errors::BridgeError, extended_rpc::ExtendedRpc};

type ChainHeadPollingResult = (
    broadcast::Sender<BitcoinSyncerEvent>,
    JoinHandle<Result<(), BridgeError>>,
);

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_hash: BlockHash,
    pub block_header: Header,
    pub block_height: u64,
}

#[derive(Clone, Debug)]
pub struct BlockInfoWithTxs {
    pub block_info: BlockInfo,
    pub txs: Vec<Transaction>,
}

#[derive(Clone, Debug)]
pub enum BitcoinSyncerEvent {
    NewBlocks(Vec<BlockInfo>),
    NewBlocksWithTxs(Vec<BlockInfoWithTxs>),
    ReorgedBlocks(Vec<BlockHash>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum BitcoinSyncerPollingMode {
    SyncOnly,
    SyncAndPollTxs,
}

pub async fn get_block_info_from_height(
    rpc: &ExtendedRpc,
    height: u64,
) -> Result<BlockInfo, BridgeError> {
    let block_hash = rpc.client.get_block_hash(height).await?;
    let block_header = rpc.client.get_block_header(&block_hash).await?;
    Ok(BlockInfo {
        block_hash,
        block_header,
        block_height: height,
    })
}

pub async fn start_bitcoin_syncer(
    db: Database,
    rpc: ExtendedRpc,
    poll_delay: Duration,
    mode: BitcoinSyncerPollingMode,
) -> Result<ChainHeadPollingResult, BridgeError> {
    let (tx, _) = broadcast::channel(100);

    let returned_tx = tx.clone();

    let mut block_height = db
        .get_max_height(None)
        .await?
        .ok_or(BridgeError::BlockNotFound)?;

    let handle = tokio::spawn(async move {
        loop {
            let mut block_hash = rpc.client.get_block_hash(block_height + 1).await?;
            let mut block_header = rpc.client.get_block_header(&block_hash).await?;

            let mut new_blocks = vec![BlockInfo {
                block_hash,
                block_header,
                block_height: block_height + 1,
            }];

            for _ in 0..100 {
                // if the previous block is in the db, do nothing
                let height = db
                    .get_height_from_block_hash(None, block_header.prev_blockhash)
                    .await?;
                if height.is_some() {
                    break;
                }

                // if the previous block is not in the db, we need to get the previous block

                block_hash = block_header.prev_blockhash;
                block_header = rpc.client.get_block_header(&block_hash).await?;

                let block_info = BlockInfo {
                    block_hash,
                    block_header,
                    block_height,
                };
                new_blocks.push(block_info);

                block_height -= 1;
            }

            // If we haven't found a match after 100 blocks, the database is too far out of sync
            if new_blocks.len() == 100 {
                return Err(BridgeError::BlockgazerTooDeep(block_height));
            }

            // check the reorg blocks
            let reorg_blocks = db.delete_chain_head_from_height(None, block_height).await?;

            if !reorg_blocks.is_empty() {
                tx.send(BitcoinSyncerEvent::ReorgedBlocks(reorg_blocks))?;
            }

            let mut dbtx = db.begin_transaction().await?;
            for block_info in new_blocks.iter() {
                db.set_chain_head(Some(&mut dbtx), block_info).await?;
            }
            dbtx.commit().await?;

            if !new_blocks.is_empty() {
                match mode {
                    BitcoinSyncerPollingMode::SyncOnly => {
                        tx.send(BitcoinSyncerEvent::NewBlocks(new_blocks))?;
                    }
                    BitcoinSyncerPollingMode::SyncAndPollTxs => {
                        let block_futures = new_blocks.iter().map(|block_info| async {
                            let block = rpc.client.get_block(&block_info.block_hash).await?;
                            Ok::<_, BridgeError>(BlockInfoWithTxs {
                                block_info: block_info.clone(),
                                txs: block.txdata,
                            })
                        });
                        let block_info_with_txs = try_join_all(block_futures).await?;
                        tx.send(BitcoinSyncerEvent::NewBlocksWithTxs(block_info_with_txs))?;
                    }
                }
            }

            sleep(poll_delay).await;
        }
    });
    Ok((returned_tx, handle))
}
