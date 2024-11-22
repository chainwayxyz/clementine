use crate::{errors::BridgeError, header_chain_prover::HeaderChainProver};
use bitcoin::BlockHash;
use bitcoin_mock_rpc::RpcApiWrapper;
use std::time::Duration;
use tokio::time::sleep;

// Checks this amount of previous blocks if not synced with blockchain.
// TODO: Get this from config file.
pub const DEEPNESS: u64 = 5;

/// Possible fetch results.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockFetchStatus {
    /// In sync with blockchain.
    UpToDate,
    /// Current tip is fallen behind with `height` and `hash`.
    FallenBehind(u64, BlockHash),
    /// Current saved tip (with `difference` specified) is too far behind the actual tip.
    OutOfBounds(u64),
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
        tracing::trace!(
            "Database blockchain tip is at height {} with block hash {}",
            db_tip_height,
            db_tip_hash
        );

        let tip_height = self.rpc.client.get_block_count()?;
        let tip_hash = self.rpc.client.get_block_hash(tip_height)?;
        let tip_prev_blockhash = self.rpc.client.get_block_header(&tip_hash)?.prev_blockhash;
        tracing::trace!(
            "Active blockchain tip is at height {} with block hash {}",
            tip_height,
            tip_hash
        );

        // Return early if database is up to date.
        if db_tip_height == tip_height && db_tip_hash == tip_hash {
            tracing::debug!("Database is in sync with active blockchain.");

            return Ok(BlockFetchStatus::UpToDate);
        }

        // Return height difference if actual tip is too far behind.
        let diff = tip_height.abs_diff(db_tip_height);
        if diff > DEEPNESS {
            tracing::error!(
                "Current tip is fallen too far behind (difference is {} blocks)!",
                diff
            );

            return Ok(BlockFetchStatus::OutOfBounds(diff));
        }

        // if hash is not matching, possible reorg might have happened.
        if (db_tip_height == tip_height && db_tip_hash != tip_hash) || (db_tip_height > tip_height)
        {
            tracing::debug!(
                "Possible reorg happened, hashes don't match for block height: {}",
                tip_height
            );

            // Check if reorg is whithin the `DEEPNESS` range. If it is, don't
            // report it as fork.
            for deepness in 1..DEEPNESS + 1 {
                let height = tip_height - deepness;
                let hash = self.rpc.client.get_block_hash(height)?;
                let db_hash = self.db.get_block_info_by_height(None, height).await?.0;

                if db_hash == hash {
                    tracing::debug!("Current database blockchain tip is {} blocks behind than the active blockchain tip.", deepness);
                    return Ok(BlockFetchStatus::FallenBehind(height, hash));
                };
            }

            tracing::error!("Current database blockchain tip is not on branch with the active blockchain (possible reorg)!");
            return Err(BridgeError::ProveError(
                "Fork happened and it is not recoverable!".to_string(),
            ));
        }

        // Go back block by block and get the latest block match with the active
        // branch.
        let mut previous_block_hash = tip_prev_blockhash;
        for deepness in 1..DEEPNESS + 1 {
            let current_block = self.rpc.client.get_block(&previous_block_hash)?;
            let current_block_hash = previous_block_hash;
            previous_block_hash = current_block.header.prev_blockhash;

            let db_block_hash = match self
                .db
                .get_block_info_by_height(None, tip_height.wrapping_sub(deepness))
                .await
            {
                Ok((block_hash, _)) => block_hash,
                Err(_) => continue,
            };

            if current_block_hash == db_block_hash {
                tracing::debug!("Current database blockchain tip is {} blocks behind than the active blockchain tip.", deepness);
                return Ok(BlockFetchStatus::FallenBehind(
                    tip_height - deepness,
                    db_block_hash,
                ));
            }
        }

        Err(BridgeError::ProveError("Unknown error".to_string()))
    }

    /// Synchronizes current database to active blockchain.
    ///
    /// It expects that current tip is not out of bounds and on the same branch
    /// as the active branch. If these conditions are not met, this could cause
    /// an infinite loop.
    ///
    /// # Parameters
    ///
    /// - current_block_height: Starts synching blocks from this height to database tip.
    async fn sync_blockchain(&self, current_block_height: u64) -> Result<(), BridgeError> {
        tracing::trace!("Synching blockchain to active blockchain.");
        let tip_height = self.rpc.client.get_block_count()?;

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
                    _ => panic!("Hapi yuttun"),
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
        extended_rpc::ExtendedRpc,
        header_chain_prover::{blockgazer::BlockFetchStatus, HeaderChainProver},
        mock::database::create_test_config_with_thread_name,
    };

    use bitcoincore_rpc::RpcApi;

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

        // Save current blockchain tip.
        let current_tip_height = rpc.client.get_block_count().unwrap();
        let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();
        let current_block = rpc.client.get_block(&current_tip_hash).unwrap();

        // Add current block to database.
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
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::OutOfBounds(diff)
        );

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
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::OutOfBounds(diff + diff2)
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_fork_basic() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Just to be safe.
        rpc.mine_blocks(1).unwrap();

        // Save current blockchain tip.
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

        // Save the next 3 blocks to database, soon to be invalidated.
        let mut fork_block_hashes = Vec::new();
        for _ in 0..3 {
            rpc.mine_blocks(1).unwrap();

            let current_tip_height = rpc.client.get_block_count().unwrap();
            let current_tip_hash = rpc.client.get_block_hash(current_tip_height).unwrap();
            let current_block_header = rpc.client.get_block(&current_tip_hash).unwrap().header;

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
