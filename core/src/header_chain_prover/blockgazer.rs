//! # Blockgazer
//!
//! Blockgazer is responsible for checking active blockchain and synching
//! current state with it.

use crate::{errors::BridgeError, header_chain_prover::HeaderChainProver};
use bitcoin::BlockHash;
use bitcoin_mock_rpc::RpcApiWrapper;
use std::time::Duration;
use tokio::time::sleep;

// Checks this amount of previous blocks if not synced with blockchain.
// TODO: Get this from config file.
pub const DEEPNESS: u64 = 6;

/// Possible fetch results.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockFetchStatus {
    /// In sync with blockchain.
    UpToDate,
    /// Current tip is fallen behind with `height` and `hash`.
    FallenBehind(u64, BlockHash),
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
    async fn check_for_new_blocks(&self) -> Result<BlockFetchStatus, BridgeError> {
        let (db_tip_height, db_tip_hash) = self.db.get_latest_block_info(None).await?;
        let tip_height = self.rpc.client.get_block_count()?;
        let tip_hash = self.rpc.client.get_block_hash(tip_height)?;
        tracing::debug!(
            "Database blockchain tip is at height {} with block hash {}",
            db_tip_height,
            db_tip_hash
        );
        tracing::debug!(
            "Active blockchain tip is at height {} with block hash {}",
            tip_height,
            tip_hash
        );

        // Return early if database is up to date.
        if db_tip_height == tip_height && db_tip_hash == tip_hash {
            tracing::trace!("Database is in sync with active blockchain.");

            return Ok(BlockFetchStatus::UpToDate);
        }

        // Return height difference if actual tip is too far behind.
        let diff = tip_height.abs_diff(db_tip_height);
        if diff > DEEPNESS {
            tracing::error!(
                "Current tip is fallen too far behind (difference is {} blocks)!",
                diff
            );

            return Err(BridgeError::BlockgazerTooDeep(diff));
        }

        // Go back block by block to check latest matched block between database
        // and active blockchain.
        let mut prev_block_hash = tip_hash;
        for deepness in 0..DEEPNESS + 1 {
            let current_block_hash = prev_block_hash;
            prev_block_hash = self
                .rpc
                .client
                .get_block_header(&current_block_hash)?
                .prev_blockhash;
            let current_block_height = tip_height.abs_diff(deepness);

            let db_block_hash = match self
                .db
                .get_block_info_by_height(None, current_block_height)
                .await
            {
                Ok((block_hash, _)) => block_hash,
                Err(e) => {
                    tracing::debug!(
                        "Block hash for height {} is not present in database: {}",
                        current_block_height,
                        e
                    );

                    continue;
                }
            };

            if current_block_hash == db_block_hash {
                tracing::debug!("Current database blockchain tip is {} blocks behind than the active blockchain tip.", deepness);

                return Ok(BlockFetchStatus::FallenBehind(
                    current_block_height,
                    db_block_hash,
                ));
            }

            tracing::debug!(
                "Block hash for height {} is not matching with active blockchain (possible reorg). Database hash: {}, active blockchain hash {}",
                current_block_height, db_block_hash, current_block_hash
            );
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
    async fn sync_blockchain(&self, current_block_height: u64) -> Result<(), BridgeError> {
        let tip_height = self.rpc.client.get_block_count()?;
        tracing::trace!(
            "{} new blocks will be written to database.",
            tip_height.abs_diff(current_block_height)
        );

        for height in (current_block_height + 1)..(tip_height + 1) {
            let hash = self.rpc.client.get_block_hash(height)?;
            let header = self.rpc.client.get_block_header(&hash)?;

            self.db.save_new_block(None, hash, header, height).await?;
        }

        Ok(())
    }

    /// Starts a Tokio task to search for new blocks. New blocks are written to
    /// database.
    ///
    /// # Parameters
    ///
    /// - prover: [`ChainProver`] instance
    /// - tx: Transmitter end for prover
    #[tracing::instrument(skip_all)]
    pub async fn start_blockgazer(prover: HeaderChainProver<R>)
    where
        R: RpcApiWrapper,
    {
        loop {
            if let Ok(status) = prover.check_for_new_blocks().await {
                match status {
                    BlockFetchStatus::UpToDate => (),
                    BlockFetchStatus::FallenBehind(block_height, _block_hash) => {
                        prover.sync_blockchain(block_height).await.unwrap();
                    }
                }
            };

            sleep(Duration::from_millis(1000)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DEEPNESS;
    use crate::{
        create_extended_rpc,
        errors::BridgeError,
        extended_rpc::ExtendedRpc,
        header_chain_prover::{blockgazer::BlockFetchStatus, HeaderChainProver},
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
            let current_tip_hash = prover
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
    async fn check_for_new_blocks_fallen_behind() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Just to be safe.
        mine_and_save_blocks(&prover, 1).await;
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Save current blockchain tip.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();

        // Falling behind some blocks should return [`BlockFetchStatus::FallenBehind`].
        let mine_count = DEEPNESS - 1;
        rpc.mine_blocks(mine_count).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, current_tip_hash)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_out_of_bounds() {
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
        let diff = DEEPNESS * DEEPNESS + DEEPNESS;
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
        let diff = DEEPNESS - 1;
        rpc.mine_blocks(diff).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, current_tip_hash)
        );

        // Exceeding deepness should return an `OutOfBounds`.
        let diff2 = DEEPNESS + DEEPNESS + 1;
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
    async fn check_for_new_blocks_fork_basic() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Just to be safe.
        mine_and_save_blocks(&prover, 1).await;
        // Save current status.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();

        // Save the next 3 blocks to database, soon to be invalidated.
        let mut fork_block_hashes = mine_and_save_blocks(&prover, 3).await;
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Invalidate previous hashes and replace them with new blocks.
        fork_block_hashes.reverse();
        fork_block_hashes
            .iter()
            .for_each(|hash| rpc.client.invalidate_block(hash).unwrap());
        rpc.mine_blocks(3).unwrap();

        // Same thing as not saving 3 blocks after they are mined.
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, current_tip_hash)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_fork_mixed() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Just to be safe.
        mine_and_save_blocks(&prover, 1).await;
        // Save current status.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();

        // Save the next 3 blocks to database, soon to be invalidated.
        let mut fork_block_hashes = mine_and_save_blocks(&prover, 3).await;
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Invalidate previous hashes and don't replace them with new blocks.
        fork_block_hashes.reverse();
        fork_block_hashes
            .iter()
            .for_each(|hash| rpc.client.invalidate_block(hash).unwrap());

        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, current_tip_hash)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sync_blockchain() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();
        let current_block = rpc.client.get_block(&current_tip_hash).unwrap();

        // Update database with current block.
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

        // Falling behind some blocks.
        rpc.mine_blocks(DEEPNESS - 1).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip_height, current_tip_hash)
        );

        // Sync database to current active blockchain.
        prover.sync_blockchain(current_tip_height).await.unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
    }
}
