//! # Bitcoin Syncer
//!
//! This module provides common utilities to fetch Bitcoin state. Other modules
//! can use this module to operate over Bitcoin. Every block starting from
//! `paramset.start_height` is fetched and stored in the database.

use crate::{
    config::protocol::ProtocolParamset,
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    task::{IntoTask, Task, TaskExt, TaskVariant, WithDelay},
};
use bitcoin::{block::Header, BlockHash, OutPoint};
use bitcoincore_rpc::RpcApi;
use eyre::Context;
use std::time::Duration;
use tonic::async_trait;

pub const BTC_SYNCER_POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(30)
};

/// Represents basic information of a Bitcoin block.
#[derive(Clone, Debug)]
struct BlockInfo {
    hash: BlockHash,
    _header: Header,
    height: u32,
}

/// Events emitted by the Bitcoin syncer.
/// It emits the block_id of the block in the db that was saved.
#[derive(Clone, Debug)]
pub enum BitcoinSyncerEvent {
    NewBlock(u32),
    ReorgedBlock(u32),
}

impl TryFrom<(String, i32)> for BitcoinSyncerEvent {
    type Error = eyre::Report;
    fn try_from(value: (String, i32)) -> Result<Self, Self::Error> {
        match value.0.as_str() {
            "new_block" => Ok(BitcoinSyncerEvent::NewBlock(
                u32::try_from(value.1).wrap_err(BridgeError::IntConversionError)?,
            )),
            "reorged_block" => Ok(BitcoinSyncerEvent::ReorgedBlock(
                u32::try_from(value.1).wrap_err(BridgeError::IntConversionError)?,
            )),
            _ => Err(eyre::eyre!("Invalid event type: {}", value.0)),
        }
    }
}

/// Trait for handling new blocks as they are finalized
#[async_trait]
pub trait BlockHandler: Send + Sync + 'static {
    /// Handle a new finalized block
    async fn handle_new_block(
        &mut self,
        dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block: bitcoin::Block,
        height: u32,
    ) -> Result<(), BridgeError>;
}

/// Fetches the [`BlockInfo`] for a given height from Bitcoin.
async fn fetch_block_info_from_height(
    rpc: &ExtendedBitcoinRpc,
    height: u32,
) -> Result<BlockInfo, BridgeError> {
    let hash = rpc
        .get_block_hash(height as u64)
        .await
        .wrap_err("Failed to get block hash")?;
    let header = rpc
        .get_block_header(&hash)
        .await
        .wrap_err("Failed to get block header")?;

    Ok(BlockInfo {
        hash,
        _header: header,
        height,
    })
}

/// Saves a Bitcoin block's metadata and it's transactions into the database.
pub(crate) async fn save_block(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    block: &bitcoin::Block,
    block_height: u32,
) -> Result<u32, BridgeError> {
    let block_hash = block.block_hash();
    tracing::debug!(
        "Saving a block with hash of {} and height of {}",
        block_hash,
        block_height
    );

    // update the block_info as canonical if it already exists
    let block_id = db.update_block_as_canonical(Some(dbtx), block_hash).await?;
    db.upsert_full_block(Some(dbtx), block, block_height)
        .await?;

    if let Some(block_id) = block_id {
        return Ok(block_id);
    }

    let block_id = db
        .insert_block_info(
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
        save_transaction_spent_utxos(db, dbtx, tx, block_id).await?;
    }

    Ok(block_id)
}
async fn _get_block_info_from_hash(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    rpc: &ExtendedBitcoinRpc,
    hash: BlockHash,
) -> Result<(BlockInfo, Vec<Vec<OutPoint>>), BridgeError> {
    let block = rpc.get_block(&hash).await.wrap_err("Failed to get block")?;
    let block_height = db
        .get_block_info_from_hash(Some(dbtx), hash)
        .await?
        .ok_or_else(|| eyre::eyre!("Block not found in get_block_info_from_hash"))?
        .1;

    let mut block_utxos: Vec<Vec<OutPoint>> = Vec::new();
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        let spent_utxos = _get_transaction_spent_utxos(db, dbtx, txid).await?;
        block_utxos.push(spent_utxos);
    }

    let block_info = BlockInfo {
        hash,
        _header: block.header,
        height: block_height,
    };

    Ok((block_info, block_utxos))
}

/// Saves a Bitcoin transaction and its spent UTXOs to the database.
async fn save_transaction_spent_utxos(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    tx: &bitcoin::Transaction,
    block_id: u32,
) -> Result<(), BridgeError> {
    let txid = tx.compute_txid();
    db.insert_txid_to_block(dbtx, block_id, &txid).await?;

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
async fn _get_transaction_spent_utxos(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    txid: bitcoin::Txid,
) -> Result<Vec<OutPoint>, BridgeError> {
    let utxos = db.get_spent_utxos_for_txid(Some(dbtx), txid).await?;
    let utxos = utxos.into_iter().map(|utxo| utxo.1).collect::<Vec<_>>();

    Ok(utxos)
}

/// If no block info exists in the DB, fetches the current block from the RPC and initializes the DB.
pub async fn set_initial_block_info_if_not_exists(
    db: &Database,
    rpc: &ExtendedBitcoinRpc,
    paramset: &'static ProtocolParamset,
) -> Result<(), BridgeError> {
    if db.get_max_height(None).await?.is_some() {
        return Ok(());
    }

    let current_height = u32::try_from(
        rpc.get_block_count()
            .await
            .wrap_err("Failed to get block count")?,
    )
    .wrap_err(BridgeError::IntConversionError)?;

    if paramset.start_height > current_height {
        tracing::error!(
            "Bitcoin syncer could not find enough available blocks in chain (Likely a regtest problem). start_height ({}) > current_height ({})",
            paramset.start_height,
            current_height
        );
        return Ok(());
    }

    let height = paramset.start_height;
    let mut dbtx = db.begin_transaction().await?;
    // first collect previous needed blocks according to paramset start height
    let block_info = fetch_block_info_from_height(rpc, height).await?;
    let block = rpc
        .get_block(&block_info.hash)
        .await
        .wrap_err("Failed to get block")?;
    let block_id = save_block(db, &mut dbtx, &block, height).await?;
    db.insert_event(Some(&mut dbtx), BitcoinSyncerEvent::NewBlock(block_id))
        .await?;

    dbtx.commit().await?;

    Ok(())
}

/// Fetches the next block from Bitcoin, if it exists. Will also fetch previous
/// blocks if the parent is missing, up to 100 blocks.
///
/// # Parameters
///
/// - `current_height`: The height of the current tip **in the database**.
///
/// # Returns
///
/// - [`None`] - If no new block is available.
/// - [`Vec<BlockInfo>`] - If new blocks are found.
async fn fetch_new_blocks(
    db: &Database,
    rpc: &ExtendedBitcoinRpc,
    current_height: u32,
) -> Result<Option<Vec<BlockInfo>>, BridgeError> {
    let next_height = current_height + 1;

    // Try to fetch the block hash for the next height.
    let block_hash = match rpc.get_block_hash(next_height as u64).await {
        Ok(hash) => hash,
        Err(_) => return Ok(None),
    };
    tracing::debug!(
        "Fetching block with hash of {:?} and height of {}...",
        block_hash,
        next_height
    );

    // Fetch its header.
    let mut block_header = rpc
        .get_block_header(&block_hash)
        .await
        .wrap_err("Failed to get block header")?;
    let mut new_blocks = vec![BlockInfo {
        hash: block_hash,
        _header: block_header,
        height: next_height,
    }];

    // Walk backwards until the parent is found in the database.
    while db
        .get_block_info_from_hash(None, block_header.prev_blockhash)
        .await?
        .is_none()
    {
        let prev_block_hash = block_header.prev_blockhash;
        block_header = rpc
            .get_block_header(&prev_block_hash)
            .await
            .wrap_err("Failed to get block header")?;
        let new_height = new_blocks.last().expect("new_blocks is empty").height - 1;
        new_blocks.push(BlockInfo {
            hash: prev_block_hash,
            _header: block_header,
            height: new_height,
        });

        if new_blocks.len() >= 100 {
            return Err(eyre::eyre!(
                "Bitcoin syncer can't synchronize database with active blockchain: Too deep to continue (last saved block was at height {})",
                new_height as u64
            )
            .into());
        }
    }

    // The chain was built from tip to fork; reverse it to be in ascending order.
    new_blocks.reverse();

    Ok(Some(new_blocks))
}

/// Marks blocks above the common ancestor as non-canonical and emits reorg events.
#[tracing::instrument(skip(db, dbtx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
async fn handle_reorg_events(
    db: &Database,
    dbtx: DatabaseTransaction<'_, '_>,
    common_ancestor_height: u32,
) -> Result<(), BridgeError> {
    let reorg_blocks = db
        .update_non_canonical_block_hashes(Some(dbtx), common_ancestor_height)
        .await?;
    if !reorg_blocks.is_empty() {
        tracing::debug!("Reorg occurred! Block ids: {:?}", reorg_blocks);
    }

    for reorg_block_id in reorg_blocks {
        db.insert_event(Some(dbtx), BitcoinSyncerEvent::ReorgedBlock(reorg_block_id))
            .await?;
    }

    Ok(())
}

/// Processes and inserts new blocks into the database, emitting a new block event for each.
async fn process_new_blocks(
    db: &Database,
    rpc: &ExtendedBitcoinRpc,
    dbtx: DatabaseTransaction<'_, '_>,
    new_blocks: &[BlockInfo],
) -> Result<(), BridgeError> {
    for block_info in new_blocks {
        let block = rpc
            .get_block(&block_info.hash)
            .await
            .wrap_err("Failed to get block")?;

        let block_id = save_block(db, dbtx, &block, block_info.height).await?;
        db.insert_event(Some(dbtx), BitcoinSyncerEvent::NewBlock(block_id))
            .await?;
    }

    Ok(())
}

/// A task that syncs Bitcoin blocks from the Bitcoin node to the local database.
#[derive(Debug)]
pub struct BitcoinSyncerTask {
    /// The database to store blocks in
    db: Database,
    /// The RPC client to fetch blocks from
    rpc: ExtendedBitcoinRpc,
    /// The current block height that has been synced
    current_height: u32,
}

#[derive(Debug)]
pub struct BitcoinSyncer {
    /// The database to store blocks in
    db: Database,
    /// The RPC client to fetch blocks from
    rpc: ExtendedBitcoinRpc,
    /// The current block height that has been synced
    current_height: u32,
}

impl BitcoinSyncer {
    /// Creates a new Bitcoin syncer task.
    ///
    /// This function initializes the database with the first block if it's empty.
    pub async fn new(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        paramset: &'static ProtocolParamset,
    ) -> Result<Self, BridgeError> {
        // Initialize the database if needed
        set_initial_block_info_if_not_exists(&db, &rpc, paramset).await?;

        // Get the current height from the database
        let current_height = db
            .get_max_height(None)
            .await?
            .ok_or_else(|| eyre::eyre!("Block not found in BitcoinSyncer::new"))?;

        Ok(Self {
            db,
            rpc,
            current_height,
        })
    }
}
impl IntoTask for BitcoinSyncer {
    type Task = WithDelay<BitcoinSyncerTask>;

    fn into_task(self) -> Self::Task {
        BitcoinSyncerTask {
            db: self.db,
            rpc: self.rpc,
            current_height: self.current_height,
        }
        .with_delay(BTC_SYNCER_POLL_DELAY)
    }
}

#[async_trait]
impl Task for BitcoinSyncerTask {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::BitcoinSyncer;

    #[tracing::instrument(skip(self))]
    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let new_blocks = match fetch_new_blocks(&self.db, &self.rpc, self.current_height).await? {
            Some(blocks) if !blocks.is_empty() => {
                tracing::debug!(
                    "{} new blocks found after current height {}",
                    blocks.len(),
                    self.current_height
                );

                blocks
            }
            _ => {
                tracing::debug!(
                    "No new blocks found after current height: {}",
                    self.current_height
                );

                return Ok(false);
            }
        };

        // The common ancestor is the block preceding the first new block.
        // Please note that this won't always be the `self.current_height`.
        // Because `fetch_next_block` can fetch older blocks, if db is missing
        // them.
        let common_ancestor_height = new_blocks[0].height - 1;
        tracing::debug!("Common ancestor height: {:?}", common_ancestor_height);
        let mut dbtx = self.db.begin_transaction().await?;

        // Mark reorg blocks (if any) as non-canonical.
        handle_reorg_events(&self.db, &mut dbtx, common_ancestor_height).await?;
        tracing::debug!("BitcoinSyncer: Marked reorg blocks as non-canonical");

        // Process and insert the new blocks.
        tracing::debug!("BitcoinSyncer: Processing new blocks");
        tracing::debug!("BitcoinSyncer: New blocks: {:?}", new_blocks.len());
        process_new_blocks(&self.db, &self.rpc, &mut dbtx, &new_blocks).await?;

        dbtx.commit().await?;

        // Update the current height to the tip of the new chain.
        tracing::debug!("BitcoinSyncer: Updating current height");
        self.current_height = new_blocks.last().expect("new_blocks is not empty").height;
        tracing::debug!("BitcoinSyncer: Current height: {:?}", self.current_height);

        // Return true to indicate work was done
        Ok(true)
    }
}

#[derive(Debug)]
pub struct FinalizedBlockFetcherTask<H: BlockHandler> {
    db: Database,
    btc_syncer_consumer_id: String,
    paramset: &'static ProtocolParamset,
    next_height: u32,
    handler: H,
}

impl<H: BlockHandler> FinalizedBlockFetcherTask<H> {
    pub fn new(
        db: Database,
        btc_syncer_consumer_id: String,
        paramset: &'static ProtocolParamset,
        next_height: u32,
        handler: H,
    ) -> Self {
        Self {
            db,
            btc_syncer_consumer_id,
            paramset,
            next_height,
            handler,
        }
    }
}

#[async_trait]
impl<H: BlockHandler> Task for FinalizedBlockFetcherTask<H> {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::FinalizedBlockFetcher;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;

        // Poll for the next bitcoin syncer event
        let Some(event) = self
            .db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.btc_syncer_consumer_id)
            .await?
        else {
            // No event found, we can safely commit the transaction and return
            dbtx.commit().await?;
            return Ok(false);
        };
        let mut new_next_height = self.next_height;

        // Process the event
        let did_find_new_block = match event {
            BitcoinSyncerEvent::NewBlock(block_id) => {
                let new_block_height = self
                    .db
                    .get_block_info_from_id(Some(&mut dbtx), block_id)
                    .await?
                    .ok_or(eyre::eyre!("Block not found in BlockFetcherTask",))?
                    .1;

                let mut new_tip = false;

                // Update states to catch up to finalized chain
                while new_block_height >= self.paramset.finality_depth
                    && new_next_height <= new_block_height - self.paramset.finality_depth
                {
                    new_tip = true;

                    let block = self
                        .db
                        .get_full_block(Some(&mut dbtx), new_next_height)
                        .await?
                        .ok_or(eyre::eyre!(
                            "Block at height {} not found in BlockFetcherTask, current tip height is {}",
                            new_next_height, new_block_height
                        ))?;

                    let new_block_id = self
                        .db
                        .get_canonical_block_id_from_height(Some(&mut dbtx), new_next_height)
                        .await?;

                    let Some(new_block_id) = new_block_id else {
                        tracing::error!("Block at height {} not found in BlockFetcherTask, current tip height is {}", new_next_height, new_block_height);
                        return Err(eyre::eyre!(
                            "Block at height {} not found in BlockFetcherTask, current tip height is {}",
                            new_next_height, new_block_height
                        ).into());
                    };

                    self.handler
                        .handle_new_block(&mut dbtx, new_block_id, block, new_next_height)
                        .await?;

                    new_next_height += 1;
                }

                new_tip
            }
            BitcoinSyncerEvent::ReorgedBlock(_) => false,
        };

        dbtx.commit().await?;
        // update next height only after db commit is successful so next_height is consistent with state in DB
        self.next_height = new_next_height;
        // Return whether we found new blocks
        Ok(did_find_new_block)
    }
}

#[cfg(test)]
mod tests {
    use crate::bitcoin_syncer::BitcoinSyncer;
    use crate::builder::transaction::DEFAULT_SEQUENCE;
    use crate::task::{IntoTask, TaskExt};
    use crate::{database::Database, test::common::*};
    use bitcoin::absolute::Height;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Transaction, TxIn, Witness};
    use bitcoincore_rpc::RpcApi;

    #[tokio::test]
    async fn get_block_info_from_height() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc.get_block_hash(height as u64).await.unwrap();
        let header = rpc.get_block_header(&hash).await.unwrap();

        let block_info = super::fetch_block_info_from_height(&rpc, height)
            .await
            .unwrap();
        assert_eq!(block_info._header, header);
        assert_eq!(block_info.hash, hash);
        assert_eq!(block_info.height, height);

        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();

        let block_info = super::fetch_block_info_from_height(&rpc, height)
            .await
            .unwrap();
        assert_ne!(block_info._header, header);
        assert_ne!(block_info.hash, hash);
        assert_eq!(block_info.height, height);
    }

    #[tokio::test]
    async fn save_get_transaction_spent_utxos() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let mut dbtx = db.begin_transaction().await.unwrap();

        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc.get_block_hash(height as u64).await.unwrap();
        let block = rpc.get_block(&hash).await.unwrap();
        let block_id = super::save_block(&db, &mut dbtx, &block, height)
            .await
            .unwrap();

        let inputs = vec![
            TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: DEFAULT_SEQUENCE,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 1,
                },
                script_sig: ScriptBuf::default(),
                sequence: DEFAULT_SEQUENCE,
                witness: Witness::default(),
            },
        ];
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: inputs.clone(),
            output: vec![],
        };
        super::save_transaction_spent_utxos(&db, &mut dbtx, &tx, block_id)
            .await
            .unwrap();

        let utxos = super::_get_transaction_spent_utxos(&db, &mut dbtx, tx.compute_txid())
            .await
            .unwrap();

        for (index, input) in inputs.iter().enumerate() {
            assert_eq!(input.previous_output, utxos[index]);
        }

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn save_get_block() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let mut dbtx = db.begin_transaction().await.unwrap();

        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc.get_block_hash(height as u64).await.unwrap();
        let block = rpc.get_block(&hash).await.unwrap();

        super::save_block(&db, &mut dbtx, &block, height)
            .await
            .unwrap();

        let (block_info, utxos) = super::_get_block_info_from_hash(&db, &mut dbtx, &rpc, hash)
            .await
            .unwrap();
        assert_eq!(block_info._header, block.header);
        assert_eq!(block_info.hash, hash);
        assert_eq!(block_info.height, height);
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            for (txin_index, txin) in tx.input.iter().enumerate() {
                assert_eq!(txin.previous_output, utxos[tx_index][txin_index]);
            }
        }

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn set_initial_block_info_if_not_exists() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let mut dbtx = db.begin_transaction().await.unwrap();

        rpc.mine_blocks(1).await.unwrap();
        // let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc
            .get_block_hash(config.protocol_paramset().start_height as u64)
            .await
            .unwrap();
        let block = rpc.get_block(&hash).await.unwrap();

        assert!(super::_get_block_info_from_hash(&db, &mut dbtx, &rpc, hash)
            .await
            .is_err());

        super::set_initial_block_info_if_not_exists(&db, &rpc, config.protocol_paramset())
            .await
            .unwrap();

        let (block_info, utxos) = super::_get_block_info_from_hash(&db, &mut dbtx, &rpc, hash)
            .await
            .unwrap();
        assert_eq!(block_info.hash, hash);
        assert_eq!(block_info.height, config.protocol_paramset().start_height);

        for (tx_index, tx) in block.txdata.iter().enumerate() {
            for (txin_index, txin) in tx.input.iter().enumerate() {
                assert_eq!(txin.previous_output, utxos[tx_index][txin_index]);
            }
        }
    }

    #[tokio::test]
    async fn fetch_new_blocks_forward() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let mut dbtx = db.begin_transaction().await.unwrap();

        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc.get_block_hash(height as u64).await.unwrap();
        let block = rpc.get_block(&hash).await.unwrap();
        super::save_block(&db, &mut dbtx, &block, height)
            .await
            .unwrap();
        dbtx.commit().await.unwrap();

        let new_blocks = super::fetch_new_blocks(&db, &rpc, height).await.unwrap();
        assert!(new_blocks.is_none());

        let new_block_hashes = rpc.mine_blocks(1).await.unwrap();
        let new_height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let new_blocks = super::fetch_new_blocks(&db, &rpc, height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(new_blocks.len(), 1);
        assert_eq!(new_blocks.first().unwrap().height, new_height);
        assert_eq!(
            new_blocks.first().unwrap().hash,
            *new_block_hashes.first().unwrap()
        );
    }

    #[tokio::test]
    async fn fetch_new_blocks_backwards() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        // Prepare chain.
        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc.get_block_hash(height as u64).await.unwrap();
        let block = rpc.get_block(&hash).await.unwrap();

        // Save the tip.
        let mut dbtx = db.begin_transaction().await.unwrap();
        super::save_block(&db, &mut dbtx, &block, height)
            .await
            .unwrap();
        dbtx.commit().await.unwrap();

        let new_blocks = super::fetch_new_blocks(&db, &rpc, height).await.unwrap();
        assert!(new_blocks.is_none());

        // Mine new blocks without saving them.
        let mine_count: u32 = 12;
        let new_block_hashes = rpc.mine_blocks(mine_count as u64).await.unwrap();
        let new_height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();

        let new_blocks = super::fetch_new_blocks(&db, &rpc, new_height - 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(new_blocks.len(), mine_count as usize);
        for (index, block) in new_blocks.iter().enumerate() {
            assert_eq!(block.height, new_height - mine_count + index as u32 + 1);
            assert_eq!(block.hash, new_block_hashes[index]);
        }

        // Mine too many blocks.
        let mine_count: u32 = 101;
        rpc.mine_blocks(mine_count as u64).await.unwrap();
        let new_height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();

        assert!(super::fetch_new_blocks(&db, &rpc, new_height - 1)
            .await
            .is_err());
    }
    #[ignore]
    #[tokio::test]
    async fn set_non_canonical_block_hashes() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let hashes = rpc.mine_blocks(4).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();

        super::set_initial_block_info_if_not_exists(&db, &rpc, config.protocol_paramset())
            .await
            .unwrap();

        rpc.invalidate_block(hashes.get(3).unwrap()).await.unwrap();
        rpc.invalidate_block(hashes.get(2).unwrap()).await.unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();

        let last_db_block =
            super::_get_block_info_from_hash(&db, &mut dbtx, &rpc, *hashes.get(3).unwrap())
                .await
                .unwrap();
        assert_eq!(last_db_block.0.height, height);
        assert_eq!(last_db_block.0.hash, *hashes.get(3).unwrap());

        super::handle_reorg_events(&db, &mut dbtx, height - 2)
            .await
            .unwrap();

        assert!(
            super::_get_block_info_from_hash(&db, &mut dbtx, &rpc, *hashes.get(3).unwrap())
                .await
                .is_err()
        );

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn start_bitcoin_syncer_new_block_mined() {
        let mut config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();
        let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
        let hash = rpc.get_block_hash(height as u64).await.unwrap();

        let (looping_task, _cancel_tx) =
            BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset())
                .await
                .unwrap()
                .into_task()
                .cancelable_loop();

        looping_task.into_bg();

        loop {
            let mut dbtx = db.begin_transaction().await.unwrap();

            let last_db_block =
                match super::_get_block_info_from_hash(&db, &mut dbtx, &rpc, hash).await {
                    Ok(block) => block,
                    Err(_) => {
                        dbtx.commit().await.unwrap();
                        continue;
                    }
                };

            assert_eq!(last_db_block.0.height, height);
            assert_eq!(last_db_block.0.hash, hash);

            dbtx.commit().await.unwrap();
            break;
        }
    }
}
