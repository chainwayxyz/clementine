//! # Blockgazer
//!
//! Blockgazer is responsible for checking active blockchain and synching
//! current state with it.

use crate::{errors::BridgeError, header_chain_prover::HeaderChainProver};
use bitcoin::BlockHash;
use bitcoin_mock_rpc::RpcApiWrapper;
use std::time::Duration;
use tokio::time::sleep;

/// Maximum height difference in batches.
const BATCH_DEEPNESS: u64 = 100;
/// Safety barrier for fetcher. This is needed for not getting effected by the
/// things like reorgs.
const BATCH_DEEPNESS_SAFETY_BARRIER: u64 = 10;

/// Blockgazer's maximum allowed height difference to handle. Above this height
/// difference, execution halts.
const MAX_ALLOWED_DISTANCE_TO_ACTIVE_TIP: u64 = 10_000;

/// Possible fetch results.
#[derive(Debug, Clone, PartialEq)]
enum BlockFetchStatus {
    /// Database is in sync with active blockchain.
    UpToDate,
    /// Database tip is fallen behind at this `block height` and this list of
    /// `block hashes`.
    FallenBehind(u64, Vec<BlockHash>),
}

impl<R> HeaderChainProver<R>
where
    R: RpcApiWrapper,
{
    /// Checks current status of the database against latest active blockchain
    /// tip.
    ///
    /// # Returns
    ///
    /// - [`BlockFetchStatus`]: Status of the current database tip
    #[tracing::instrument(skip(self))]
    async fn check_for_new_blocks(&self) -> Result<BlockFetchStatus, BridgeError> {
        let (db_tip_height, db_tip_hash) = self.db.get_latest_block_info(None).await?;
        let active_tip_height = self.rpc.client.get_block_count()?;
        let active_tip_hash = self.rpc.client.get_block_hash(active_tip_height)?;
        tracing::debug!(
            "Database blockchain tip is at height {} with block hash {}",
            db_tip_height,
            db_tip_hash
        );
        tracing::debug!(
            "Active blockchain tip is at height {} with block hash {}",
            active_tip_height,
            active_tip_hash
        );

        // Return early if database is up to date.
        if db_tip_height == active_tip_height && db_tip_hash == active_tip_hash {
            tracing::trace!("Database is in sync with active blockchain.");

            return Ok(BlockFetchStatus::UpToDate);
        }

        // Return height difference if actual tip is too far behind.
        let diff = active_tip_height.abs_diff(db_tip_height);
        if diff > MAX_ALLOWED_DISTANCE_TO_ACTIVE_TIP {
            tracing::error!(
                "Current tip is fallen too far behind (difference is {} blocks)!",
                diff
            );

            return Err(BridgeError::BlockgazerTooDeep(diff));
        }

        // Check if active blockchain tip is too far away or in batch bounds. If
        // it is too far away, just fetch a batch of hashes.
        let (height, hash) = if active_tip_height < db_tip_height + BATCH_DEEPNESS {
            (active_tip_height, active_tip_hash)
        } else {
            let new_height = db_tip_height + BATCH_DEEPNESS - BATCH_DEEPNESS_SAFETY_BARRIER;

            (new_height, self.rpc.client.get_block_hash(new_height)?)
        };
        tracing::debug!("Fetching blocks between {db_tip_height}-{height}");

        // Go back block by block to check latest matched block between database
        // and active blockchain.
        let mut block_hashes = Vec::new();
        let mut prev_block_hash = hash;
        for deepness in 0..BATCH_DEEPNESS {
            let current_block_hash = prev_block_hash;
            block_hashes.push(current_block_hash);
            let current_block_height = height.abs_diff(deepness);

            prev_block_hash = self
                .rpc
                .client
                .get_block_header(&current_block_hash)?
                .prev_blockhash;

            let header = self
                .db
                .get_block_header(None, current_block_height, current_block_hash)
                .await;

            match header {
                Ok(Some(_)) => {
                    tracing::debug!("Current database blockchain tip is {} blocks behind than the active blockchain tip.", deepness);

                    // Remove hash that is already present in database.
                    block_hashes.pop();
                    // TODO: Should this list be reversed so it matches the real
                    // block ordering? This won't introduce any meaningful benefits.
                    // It will become more intuitive, with the cost of performance.

                    return Ok(BlockFetchStatus::FallenBehind(
                        current_block_height,
                        block_hashes,
                    ));
                }
                Ok(None) => {
                    tracing::debug!(
                        "Block hash for height {} is not matching with active blockchain (possible reorg). Active blockchain hash {}",
                        current_block_height, current_block_hash
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        "Block hash for height {} is not present in database: {}",
                        current_block_height,
                        e
                    );

                    continue;
                }
            };
        }

        Err(BridgeError::BlockgazerFork)
    }

    /// Synchronizes current database to active blockchain. It starts fetching
    /// new blocks, starting with given height and runs until it's in sync with
    /// current active tip.
    ///
    /// # Parameters
    ///
    /// - `current_block_height`: Starts synching blocks from this height to
    ///   active blockchain tip.
    ///
    /// # Errors
    ///
    /// If tip height gets lower than the start, mid-sync, this will return error.
    /// Also, mid-sync reorgs are not handled.
    async fn sync_blockchain(
        &self,
        current_block_height: u64,
        hashes: Vec<BlockHash>,
    ) -> Result<(), BridgeError> {
        tracing::trace!("{} new blocks will be written to database.", hashes.len());

        for i in 0..hashes.len() {
            let block_hash = hashes[i];

            let block_header = self.rpc.client.get_block_header(&block_hash)?;

            let diff = hashes.len() - i;
            let block_height = current_block_height + diff as u64;

            self.db
                .save_new_block(None, block_hash, block_header, block_height)
                .await?;
        }

        Ok(())
    }

    /// Starts an async task to search for new blocks. New blocks are written to
    /// database.
    ///
    /// # Parameters
    ///
    /// TODO: Use `&self`.
    ///
    /// - prover: [`ChainProver`] instance
    #[tracing::instrument(skip_all)]
    pub async fn start_blockgazer(prover: HeaderChainProver<R>)
    where
        R: RpcApiWrapper,
    {
        loop {
            if let Ok(status) = prover.check_for_new_blocks().await {
                match status {
                    BlockFetchStatus::UpToDate => (),
                    BlockFetchStatus::FallenBehind(block_height, block_hashes) => {
                        prover
                            .sync_blockchain(block_height, block_hashes)
                            .await
                            .unwrap();
                    }
                }
            };

            sleep(Duration::from_millis(1000)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        create_extended_rpc,
        errors::BridgeError,
        extended_rpc::ExtendedRpc,
        header_chain_prover::{
            blockgazer::{BlockFetchStatus, BATCH_DEEPNESS, BATCH_DEEPNESS_SAFETY_BARRIER},
            HeaderChainProver,
        },
        mock::database::create_test_config_with_thread_name,
    };
    use bitcoin::BlockHash;
    use bitcoin_mock_rpc::RpcApiWrapper;
    use bitcoincore_rpc::RpcApi;

    async fn mine_and_save_blocks<R>(prover: &HeaderChainProver<R>, height: u64) -> Vec<BlockHash>
    where
        R: RpcApiWrapper,
    {
        let mut fork_block_hashes = Vec::new();
        for _ in 0..height {
            prover.rpc.mine_blocks(1).unwrap();

            let current_tip_height = prover.rpc.client.get_block_count().unwrap();
            let current_tip_hash: BlockHash = prover
                .rpc
                .client
                .get_block_hash(current_tip_height)
                .unwrap();
            let current_block_header = prover
                .rpc
                .client
                .get_block(&current_tip_hash)
                .unwrap()
                .header;

            prover
                .db
                .save_new_block(
                    None,
                    current_tip_hash,
                    current_block_header,
                    current_tip_height,
                )
                .await
                .unwrap();

            fork_block_hashes.push(current_tip_hash);
        }

        fork_block_hashes
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_uptodate() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();
        let current_block = rpc.client.get_block(&current_tip_hash).unwrap();

        // Updating database with current block should return [`BlockFetchStatus::UpToDate`].
        prover
            .db
            .save_new_block(
                None,
                current_tip_hash,
                current_block.header,
                current_tip_height,
            )
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_fallen_behind_single() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Mine initial block and save it to database.
        let block_hashes = mine_and_save_blocks(&prover, 1).await;
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
        assert_eq!(block_hashes.len(), 1);
        let current_tip_height = rpc.client.get_block_count().unwrap();
        println!(
            "Initial block height is {current_tip_height} and hash is {}",
            *block_hashes.first().unwrap()
        );

        // Mine a block but don't save it to database.
        rpc.mine_blocks(1).unwrap();
        let current_tip_hash = rpc
            .client
            .get_block_hash(rpc.client.get_block_count().unwrap())
            .unwrap();
        assert_ne!(current_tip_hash, *block_hashes.first().unwrap());

        // Falling behind just a block should return that block's hash.
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, vec![current_tip_hash])
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_fallen_behind_multiple() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Mine initial block and save it to database.
        let block_hashes = mine_and_save_blocks(&prover, 1).await;
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
        assert_eq!(block_hashes.len(), 1);
        let current_tip_height = rpc.client.get_block_count().unwrap();
        println!(
            "Initial block height is {current_tip_height} and hash is {}",
            *block_hashes.first().unwrap()
        );

        // Mine some block but don't save them to database.
        let amount = BATCH_DEEPNESS - BATCH_DEEPNESS_SAFETY_BARRIER - 1;
        rpc.mine_blocks(amount).unwrap();
        let height = rpc.client.get_block_count().unwrap();

        // Get the block hash list of unsaved blocks.
        let mut block_hashes = Vec::new();
        for diff in 0..amount {
            block_hashes.push(rpc.client.get_block_hash(height - diff).unwrap());
        }

        // Falling behind some blocks should return those blocks' hash.
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, block_hashes)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "Mining too much blocks slows down testing. TODO: Change steps"]
    async fn check_for_new_blocks_too_deep() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Add current block to database.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();
        let current_block = rpc.client.get_block(&current_tip_hash).unwrap();
        prover
            .db
            .save_new_block(
                None,
                current_tip_hash,
                current_block.header,
                current_tip_height,
            )
            .await
            .unwrap();

        // Mining some blocks and not updating database should cause a
        // [`BlockFetchStatus::OutOfBounds`] return.
        let diff = BATCH_DEEPNESS * BATCH_DEEPNESS + BATCH_DEEPNESS;
        rpc.mine_blocks(diff).unwrap();
        let err = prover.check_for_new_blocks().await.err().unwrap();
        if let BridgeError::BlockgazerTooDeep(bdiff) = err {
            assert_eq!(bdiff, diff);
        } else {
            panic!("Wrong error type!");
        }

        // Add current block to database.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();
        let current_block = rpc.client.get_block(&current_tip_hash).unwrap();
        prover
            .db
            .save_new_block(
                None,
                current_tip_hash,
                current_block.header,
                current_tip_height,
            )
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Not exceeding deepness should not return an `OutOfBounds`.
        let diff = BATCH_DEEPNESS - 1;
        rpc.mine_blocks(diff).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, vec![current_tip_hash])
        );

        // Exceeding deepness should return an `OutOfBounds`.
        let diff2 = BATCH_DEEPNESS + BATCH_DEEPNESS + 1;
        rpc.mine_blocks(diff2).unwrap();
        let err = prover.check_for_new_blocks().await.err().unwrap();
        if let BridgeError::BlockgazerTooDeep(bdiff) = err {
            assert_eq!(bdiff, diff + diff2);
        } else {
            panic!("Wrong error type!");
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_fork_and_mine_new() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save initial block.
        mine_and_save_blocks(&prover, 1).await;
        let initial_tip_height = rpc.client.get_block_count().unwrap();

        // Save the next 3 blocks to database, then invalidate.
        let mut fork_block_hashes = mine_and_save_blocks(&prover, 3).await;
        fork_block_hashes.reverse();
        fork_block_hashes
            .iter()
            .for_each(|hash| rpc.client.invalidate_block(hash).unwrap());

        let mut hashes = rpc.mine_blocks(3).unwrap();
        hashes.reverse();

        // Same thing as not saving 3 blocks after they are mined.
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(initial_tip_height, hashes)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sync_blockchain_single_block() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        mine_and_save_blocks(&prover, 1).await;
        let current_tip_height = rpc.client.get_block_count().unwrap();

        // Falling behind some blocks.
        let hash = rpc.mine_blocks(1).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, hash.clone())
        );

        // Sync database to current active blockchain.
        prover
            .sync_blockchain(current_tip_height, hash)
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sync_blockchain_multiple_blocks() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        mine_and_save_blocks(&prover, 1).await;
        let current_tip_height = rpc.client.get_block_count().unwrap();

        // Falling behind some blocks.
        let mut hash = rpc.mine_blocks(10).unwrap();
        hash.reverse();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, hash.clone())
        );

        // Sync database to current active blockchain.
        prover
            .sync_blockchain(current_tip_height, hash)
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sync_blockchain_multiple_blocks_with_fork() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        mine_and_save_blocks(&prover, 1).await;
        let current_tip_height = rpc.client.get_block_count().unwrap();

        // Falling behind some blocks and recovering from it.
        let mut hash = rpc.mine_blocks(10).unwrap();
        hash.reverse();
        prover
            .sync_blockchain(current_tip_height, hash.clone())
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Latest block got invalidated, later to be replaced with new block.
        rpc.client.invalidate_block(hash.first().unwrap()).unwrap();
        let current_tip_height = rpc.client.get_block_count().unwrap();
        assert_ne!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Synching should recover state after mining new blocks.
        let hashes = rpc.mine_blocks(1).unwrap();
        prover
            .sync_blockchain(current_tip_height, hashes)
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
    }
}
