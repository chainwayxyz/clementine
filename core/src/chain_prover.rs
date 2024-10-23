//! # Header Chain Prover
//!
//! Fetches latest blocks from Bitcoin and prepares proves for them.

use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError, extended_rpc::ExtendedRpc,
};
use bitcoin::{block, BlockHash};
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::json::GetChainTipsResultStatus;

// Checks this amount of previous blocks if not synced with blockchain.
// TODO: Get this from config file.
const DEEPNESS: u64 = 5;

/// Possible fetch results.
#[derive(Debug, Clone, Copy, PartialEq)]
enum BlockFetchStatus {
    /// In sync with blockchain.
    UpToDate,
    /// Current tip is fallen behind with `height` and `hash`.
    FallenBehind(u64, BlockHash),
    /// Current saved tip (with `height` specified) is too far behind the actual tip.
    OutOfBounds(u64),
    /// Current tip is considered a fork with `height` and `hash`.
    Fork(u64, BlockHash),
}

#[derive(Debug, Clone)]
pub struct ChainProver<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    db: Database,
}

impl<R> ChainProver<R>
where
    R: RpcApiWrapper,
{
    pub async fn new(config: &BridgeConfig, rpc: ExtendedRpc<R>) -> Result<Self, BridgeError> {
        let db = Database::new(config).await?;

        Ok(ChainProver { rpc, db })
    }

    /// Get the proof of a block.
    ///
    /// # Parameters
    ///
    /// - `height`: Target block height
    /// - `hash`: [Optional] Target block hash
    pub async fn get_header_chain_proof(_height: u64, _hash: Option<block::BlockHash>) {
        todo!()
    }

    /// Starts a background task that syncs current database to active
    /// blockchain and does proving.
    pub fn start_block_prover(&'static self) {
        tokio::spawn(async move {
            loop {
                let _status = self.check_for_new_blocks().await;
                self.sync_blockchain().await;
                self.prove_block().await;
            }
        });

        todo!()
    }

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

        let tips = self.rpc.client.get_chain_tips()?;
        let tip = tips
            .iter()
            .find(|tip| tip.status == GetChainTipsResultStatus::Active)
            .ok_or(BridgeError::BlockNotFound)?;
        let tip_height = tip.height;
        let tip_hash = tip.hash;
        let tip_block = self.rpc.client.get_block(&tip_hash)?;
        tracing::trace!(
            "Active blockchain tip is at height {} with block hash {}",
            tip_height,
            tip_hash
        );

        // Return early if database is up to date.
        if db_tip_height == tip_height && db_tip_hash == tip_hash {
            return Ok(BlockFetchStatus::UpToDate);
        }

        // Return current height if actual tip is too far behind.
        if db_tip_height + DEEPNESS < tip_height {
            tracing::error!("Current tip is fallen too far behind!");

            return Ok(BlockFetchStatus::OutOfBounds(db_tip_height));
        }

        // Go back block by block to check that we are still at the same branch
        // as the active blockchain.
        let mut previous_block_hash = tip_block.header.prev_blockhash;
        for deepness in 1..DEEPNESS + 1 {
            let current_block = self.rpc.client.get_block(&previous_block_hash)?;
            let current_block_hash = previous_block_hash;
            previous_block_hash = current_block.header.prev_blockhash;

            let db_block_hash = match self
                .db
                .get_block_proof_info_by_height(None, tip_height - deepness)
                .await
            {
                Ok(r) => r.0,
                Err(_) => continue,
            };

            if current_block_hash == db_block_hash {
                tracing::trace!("Current database blockchain tip is {} blocks behind than the active blockchain tip.", deepness);

                return Ok(BlockFetchStatus::FallenBehind(
                    tip_height - deepness,
                    db_block_hash,
                ));
            }
        }

        tracing::error!("Current database blockchain tip is not on branch with the active blockchain (possible reorg)!");

        Ok(BlockFetchStatus::Fork(db_tip_height, db_tip_hash))
    }

    async fn sync_blockchain(&self) {
        todo!()
    }

    async fn prove_block(&self) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chain_prover::{BlockFetchStatus, ChainProver, DEEPNESS},
        create_extended_rpc,
        extended_rpc::ExtendedRpc,
        mock::database::create_test_config_with_thread_name,
    };
    use bitcoincore_rpc::{json::GetChainTipsResultStatus, RpcApi};

    #[tokio::test]
    async fn new() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);

        let _should_not_panic = ChainProver::new(&config, rpc).await.unwrap();
    }

    #[tokio::test]
    async fn check_for_new_blocks() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        let current_tip = rpc.client.get_chain_tips().unwrap();
        let current_tip = current_tip.first().unwrap();
        assert_eq!(current_tip.status, GetChainTipsResultStatus::Active);
        let current_block = rpc.client.get_block(&current_tip.hash).unwrap();

        // Updating database with current block should return [`BlockFetchStatus::UpToDate`].
        prover
            .db
            .save_new_block(
                None,
                current_tip.hash,
                current_block.header,
                current_tip.height as u32,
            )
            .await
            .unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );

        // Falling behind some blocks should return [`BlockFetchStatus::FallenBehind`].
        rpc.mine_blocks(DEEPNESS - 1).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip.height, current_tip.hash)
        );

        // Mining some blocks and not updating database should cause a
        // [`BlockFetchStatus::OutOfBounds`] return.
        rpc.mine_blocks(DEEPNESS + 1).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::OutOfBounds(current_tip.height)
        );
    }
}
