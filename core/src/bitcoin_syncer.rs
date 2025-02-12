//! # Bitcoin Syncer
//!
//! This module provides common utilities to fetch Bitcoin state. Other modules
//! can use this module to operate over Bitcoin.

use crate::{
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};
use bitcoin::{block::Header, BlockHash};
use bitcoincore_rpc::RpcApi;
use std::time::Duration;
use tokio::{task::JoinHandle, time::sleep};

/// Represents basic information of a Bitcoin block.
#[derive(Clone, Debug)]
struct BlockInfo {
    hash: BlockHash,
    _header: Header,
    height: u64,
}

/// Events emitted by the Bitcoin syncer.
#[derive(Clone, Debug)]
pub enum BitcoinSyncerEvent {
    NewBlock(BlockHash),
    ReorgedBlock(BlockHash),
}

/// Fetches the [`BlockInfo`] for a given height from Bitcoin.
async fn get_block_info_from_height(
    rpc: &ExtendedRpc,
    height: u64,
) -> Result<BlockInfo, BridgeError> {
    let hash = rpc.client.get_block_hash(height).await?;
    let header = rpc.client.get_block_header(&hash).await?;

    Ok(BlockInfo {
        hash,
        _header: header,
        height,
    })
}

/// Saves a Bitcoin block's [`BlockInfo`] and it's transactions into the
/// database.
async fn save_block(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    block: &bitcoin::Block,
    block_height: i64,
) -> Result<(), BridgeError> {
    let block_hash = block.header.block_hash();
    tracing::debug!(
        "Saving a block with hash of {} and height of {}",
        block_hash,
        block_height
    );

    let block_id = db
        .add_block_info(
            Some(dbtx),
            &block_hash,
            &block.header.prev_blockhash,
            block_height,
        )
        .await?;

    tracing::debug!(
        "Saving {} transactions to a block with hash {}",
        block.txdata.len(),
        block_hash
    );
    for tx in &block.txdata {
        save_transaction(db, dbtx, tx, block_id).await?;
    }

    Ok(())
}

/// Saves a Bitcoin transaction and its spent UTXOs to the database.
async fn save_transaction(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    tx: &bitcoin::Transaction,
    block_id: u32,
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

    Ok(())
}

/// If no block info exists in the DB, fetches the current block from the RPC and initializes the DB.
pub async fn set_initial_block_info_if_not_exists(
    db: &Database,
    rpc: &ExtendedRpc,
) -> Result<(), BridgeError> {
    if db.get_max_height(None).await?.is_some() {
        return Ok(());
    }

    let current_height = rpc.client.get_block_count().await?;
    let block_info = get_block_info_from_height(rpc, current_height).await?;
    let block = rpc.client.get_block(&block_info.hash).await?;

    let mut dbtx = db.begin_transaction().await?;

    save_block(db, &mut dbtx, &block, current_height as i64).await?;
    db.add_event(
        Some(&mut dbtx),
        BitcoinSyncerEvent::NewBlock(block_info.hash),
    )
    .await?;

    dbtx.commit().await?;

    Ok(())
}

/// Fetches new blocks from Bitcoin, starting from given height.
///
/// It first tries to fetch the block at the next height. If its parent is missing
/// from the database, it walks backward (up to 100 blocks) to retrieve the entire new chain.
/// Returns `Ok(Some(new_blocks))` if new blocks are found or `Ok(None)` if no new block is available.
async fn fetch_new_blocks(
    db: &Database,
    rpc: &ExtendedRpc,
    current_height: u64,
) -> Result<Option<Vec<BlockInfo>>, BridgeError> {
    let next_height = current_height + 1;

    // Try to fetch the block hash for the next height.
    let block_hash = match rpc.client.get_block_hash(next_height).await {
        Ok(hash) => hash,
        Err(_) => return Ok(None),
    };

    // Fetch its header.
    let mut block_header = rpc.client.get_block_header(&block_hash).await?;
    let mut new_blocks = vec![BlockInfo {
        hash: block_hash,
        _header: block_header,
        height: next_height,
    }];

    // Walk backwards until the parent is found in the database.
    while db
        .get_height_from_block_hash(None, block_header.prev_blockhash)
        .await?
        .is_none()
    {
        let prev_block_hash = block_header.prev_blockhash;
        block_header = rpc.client.get_block_header(&prev_block_hash).await?;
        let new_height = new_blocks.last().expect("new_blocks is empty").height - 1;
        new_blocks.push(BlockInfo {
            hash: prev_block_hash,
            _header: block_header,
            height: new_height,
        });

        if new_blocks.len() >= 100 {
            return Err(BridgeError::BlockgazerTooDeep(new_height));
        }
    }

    // The chain was built from tip to fork; reverse it to be in ascending order.
    new_blocks.reverse();

    Ok(Some(new_blocks))
}

/// Marks blocks above the common ancestor as non-canonical and emits reorg events.
async fn handle_reorg_events(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    common_ancestor_height: u64,
) -> Result<(), BridgeError> {
    let reorg_blocks = db
        .set_non_canonical_block_hashes(Some(dbtx), common_ancestor_height)
        .await?;
    for reorg_hash in reorg_blocks {
        db.add_event(Some(dbtx), BitcoinSyncerEvent::ReorgedBlock(reorg_hash))
            .await?;
    }

    Ok(())
}

/// Processes and inserts new blocks into the database, emitting a new block event for each.
async fn process_new_blocks(
    db: &Database,
    rpc: &ExtendedRpc,
    dbtx: DatabaseTransaction<'_, '_>,
    new_blocks: &[BlockInfo],
) -> Result<(), BridgeError> {
    for block_info in new_blocks {
        let block = rpc.client.get_block(&block_info.hash).await?;

        save_block(db, dbtx, &block, block_info.height as i64).await?;
        db.add_event(Some(dbtx), BitcoinSyncerEvent::NewBlock(block_info.hash))
            .await?;
    }

    Ok(())
}

/// Starts the Bitcoin syncer loop which continuously polls for new blocks, processes them,
/// and handles potential reorganizations. Returns a [`JoinHandle`] for the background task.
pub async fn start_bitcoin_syncer(
    db: Database,
    rpc: ExtendedRpc,
    poll_delay: Duration,
) -> Result<JoinHandle<Result<(), BridgeError>>, BridgeError> {
    set_initial_block_info_if_not_exists(&db, &rpc).await?;

    let mut current_height = db
        .get_max_height(None)
        .await?
        .ok_or(BridgeError::BlockNotFound)?;

    let handle = tokio::spawn(async move {
        loop {
            // Try to fetch new blocks (if any) from the RPC.
            let maybe_new_blocks = fetch_new_blocks(&db, &rpc, current_height).await?;
            let new_blocks = match maybe_new_blocks {
                Some(blocks) if !blocks.is_empty() => blocks,
                _ => {
                    sleep(poll_delay).await;
                    continue;
                }
            };

            // The common ancestor is the block preceding the first new block.
            let common_ancestor_height =
                new_blocks.first().expect("new_blocks is empty").height - 1;
            let mut dbtx = db.begin_transaction().await?;

            // Mark reorg blocks (if any) as non-canonical.
            handle_reorg_events(&db, &mut dbtx, common_ancestor_height).await?;
            // Process and insert the new blocks.
            process_new_blocks(&db, &rpc, &mut dbtx, &new_blocks).await?;
            dbtx.commit().await?;

            // Update the current height to the tip of the new chain.
            current_height = new_blocks.last().expect("new_blocks is empty").height;
            sleep(poll_delay).await;
        }
    });
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::RpcApi;
    use crate::create_test_config_with_thread_name;
    use crate::extended_rpc::ExtendedRpc;
    use crate::{
        config::BridgeConfig, database::Database, initialize_database, utils::initialize_logger,
    };

    #[tokio::test]
    #[serial_test::serial]
    async fn get_block_info_from_height() {
        let config = create_test_config_with_thread_name!(None);
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        rpc.mine_blocks(1).await.unwrap();
        let height = rpc.client.get_block_count().await.unwrap();
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let header = rpc.client.get_block_header(&hash).await.unwrap();

        let block_info = super::get_block_info_from_height(&rpc, height).await.unwrap();
        assert_eq!(block_info._header, header);
        assert_eq!(block_info.hash, hash);
        assert_eq!(block_info.height, height);

        rpc.mine_blocks(1).await.unwrap();
        let height = rpc.client.get_block_count().await.unwrap();

        let block_info = super::get_block_info_from_height(&rpc, height).await.unwrap();
        assert_ne!(block_info._header, header);
        assert_ne!(block_info.hash, hash);
        assert_eq!(block_info.height, height);
    }
}
