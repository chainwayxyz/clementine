use std::time::Duration;

use bitcoin::{block::Header, BlockHash};
use bitcoincore_rpc::RpcApi;
use tokio::{task::JoinHandle, time::sleep};

use crate::{
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_hash: BlockHash,
    pub block_header: Header,
    pub block_height: u64,
}

#[derive(Clone, Debug)]
pub enum BitcoinSyncerEvent {
    NewBlock(BlockHash),
    ReorgedBlock(BlockHash),
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

pub async fn process_block(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    block: &bitcoin::Block,
    block_height: i64,
) -> Result<(), BridgeError> {
    let block_hash = block.header.block_hash();

    tracing::info!("Adding block info");
    let block_id = db
        .add_block_info(
            Some(dbtx),
            &block_hash,
            &block.header.prev_blockhash,
            block_height,
        )
        .await?;

    tracing::info!("Processing txs");
    for tx in &block.txdata {
        process_tx(db, dbtx, tx, block_id).await?;
    }
    Ok::<(), BridgeError>(())
}

pub async fn process_tx(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    tx: &bitcoin::Transaction,
    block_id: i32,
) -> Result<(), BridgeError> {
    let txid = tx.compute_txid();
    db.insert_tx(dbtx, block_id, &txid).await?;

    for input in &tx.input {
        db.insert_spent_utxo(
            dbtx,
            block_id,
            &txid,
            &input.previous_output.txid,
            input.previous_output.vout as i64,
        )
        .await?;
    }

    Ok::<(), BridgeError>(())
}

pub async fn set_initial_block_info_if_not_exists(
    db: &Database,
    rpc: &ExtendedRpc,
) -> Result<(), BridgeError> {
    // if the block info is already set, do nothing
    if db.get_max_height(None).await?.is_some() {
        return Ok(());
    }
    let current_height = rpc.client.get_block_count().await?;
    let current_block_info = get_block_info_from_height(rpc, current_height).await?;
    let block = rpc.client.get_block(&current_block_info.block_hash).await?;
    let mut dbtx = db.begin_transaction().await?;
    process_block(db, &mut dbtx, &block, current_height as i64).await?;
    db.add_event(
        Some(&mut dbtx),
        BitcoinSyncerEvent::NewBlock(current_block_info.block_hash),
    )
    .await?;
    dbtx.commit().await?;
    Ok(())
}

pub async fn start_bitcoin_syncer(
    db: Database,
    rpc: ExtendedRpc,
    poll_delay: Duration,
) -> Result<JoinHandle<Result<(), BridgeError>>, BridgeError> {
    set_initial_block_info_if_not_exists(&db, &rpc).await?;

    let mut block_height = db
        .get_max_height(None)
        .await?
        .ok_or(BridgeError::BlockNotFound)?;

    let handle = tokio::spawn(async move {
        let mut block_hash;
        loop {
            let block_hash_response = rpc.client.get_block_hash(block_height + 1).await;
            if let Err(_e) = &block_hash_response {
                sleep(poll_delay).await;
                continue;
            }
            block_hash = block_hash_response.expect("Block hash should be found");

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

            let mut dbtx = db.begin_transaction().await?;
            // check the reorg blocks
            let reorg_blocks = db
                .set_non_canonical_block_hashes(Some(&mut dbtx), block_height)
                .await?;

            if !reorg_blocks.is_empty() {
                for block_hash in reorg_blocks {
                    db.add_event(
                        Some(&mut dbtx),
                        BitcoinSyncerEvent::ReorgedBlock(block_hash),
                    )
                    .await?;
                }
            }

            for block_info in new_blocks.iter() {
                let block = rpc.client.get_block(&block_info.block_hash).await?;
                process_block(&db, &mut dbtx, &block, block_height as i64).await?;
            }

            for block_info in new_blocks.iter() {
                db.add_event(
                    Some(&mut dbtx),
                    BitcoinSyncerEvent::NewBlock(block_info.block_hash),
                )
                .await?;
            }

            block_height += 1;

            dbtx.commit().await?;

            sleep(poll_delay).await;
        }
    });
    Ok(handle)
}
