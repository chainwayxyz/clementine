//! # Header Chain Prover
//!
//! Fetches latest blocks from Bitcoin and prepares proves for them.

use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError, extended_rpc::ExtendedRpc,
};
use bitcoin::{
    block::{self, Header},
    hashes::Hash,
    BlockHash, Work,
};
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::json::{GetChainTipsResultStatus, GetChainTipsResultTip};
use risc0_zkvm::{AssumptionReceipt, ExecutorEnv, Receipt};

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

/// Input data for a proof.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofData {
    pub genesis_block_hash: BlockHash,
    pub is_genesis: bool,
    pub prev_method_id: [u32; 8],
    pub prev_offset: u32,
    pub prev_block_hash: BlockHash,
    pub prev_total_work: Work,
    pub return_offset: u32,
    pub header_batch: Vec<Header>,
}

impl Default for ProofData {
    fn default() -> Self {
        Self {
            genesis_block_hash: BlockHash::all_zeros(),
            is_genesis: true,
            prev_method_id: [0; 8],
            prev_offset: 0,
            prev_block_hash: BlockHash::all_zeros(),
            prev_total_work: Work::from_hex("0x0").unwrap(),
            return_offset: 0,
            header_batch: vec![],
        }
    }
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
                self.sync_blockchain().await.unwrap();
                let _proof = self
                    .prove_block(ProofData::default(), None::<Receipt>)
                    .await
                    .unwrap();
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

        let tip = self.get_active_tip()?;
        let tip_block = self.rpc.client.get_block(&tip.hash)?;

        // Return early if database is up to date. Or if hash is not matching,
        // possible reorg might have happened.
        if db_tip_height == tip.height && db_tip_hash == tip.hash {
            return Ok(BlockFetchStatus::UpToDate);
        } else if db_tip_height == tip.height && db_tip_hash != tip.hash {
            tracing::error!("Current database blockchain tip is not on branch with the active blockchain (possible reorg)!");

            return Ok(BlockFetchStatus::Fork(db_tip_height, db_tip_hash));
        }

        // Return current height if actual tip is too far behind.
        if db_tip_height + DEEPNESS < tip.height {
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
                .get_block_proof_info_by_height(None, tip.height - deepness)
                .await
            {
                Ok(r) => r.0,
                Err(_) => continue,
            };

            if current_block_hash == db_block_hash {
                tracing::trace!("Current database blockchain tip is {} blocks behind than the active blockchain tip.", deepness);

                return Ok(BlockFetchStatus::FallenBehind(
                    tip.height - deepness,
                    db_block_hash,
                ));
            }
        }

        tracing::error!("Current database blockchain tip is not on branch with the active blockchain (possible reorg)!");

        Ok(BlockFetchStatus::Fork(db_tip_height, db_tip_hash))
    }

    /// Synchronizes current database to active blockchain.
    ///
    /// It expects that current tip is not out of bounds and on the same branch
    /// as the active branch. If these conditions are not met, this could cause
    /// an infinite loop.
    async fn sync_blockchain(&self) -> Result<(), BridgeError> {
        let height = self.rpc.client.get_block_count()?;
        let (db_tip_height, _) = self.db.get_latest_block_info(None).await?;

        for height in (db_tip_height + 1)..(height + 1) {
            let hash = self.rpc.client.get_block_hash(height)?;
            let header = self.rpc.client.get_block_header(&hash)?;

            self.db
                .save_new_block(None, hash, header, height as u32)
                .await?;
        }

        Ok(())
    }

    /// Prove a block.
    ///
    /// # Parameters
    ///
    /// - proof_data: Target block's information
    ///
    /// # Returns
    ///
    /// - TODO
    async fn prove_block(
        &self,
        proof_data: ProofData,
        assumption: Option<impl Into<AssumptionReceipt>>,
    ) -> Result<(Receipt, ([u32; 8], [u8; 32], u32, [u8; 32], [u8; 32])), BridgeError> {
        let mut env = ExecutorEnv::builder();

        if let Some(assumption) = assumption {
            env.add_assumption(assumption);
        }

        env.write(&proof_data.genesis_block_hash.as_raw_hash().as_byte_array())
            .unwrap()
            .write(&proof_data.is_genesis)
            .unwrap();

        if proof_data.is_genesis {
            env.write(&proof_data.prev_method_id)
                .unwrap()
                .write(&proof_data.return_offset)
                .unwrap()
                .write(&proof_data.header_batch.len())
                .unwrap();
        } else {
            env.write(&proof_data.prev_method_id)
                .unwrap()
                .write(&proof_data.prev_offset)
                .unwrap()
                .write(&proof_data.prev_block_hash.as_raw_hash().as_byte_array())
                .unwrap()
                .write(&proof_data.prev_total_work.to_be_bytes())
                .unwrap()
                .write(&proof_data.return_offset)
                .unwrap()
                .write(&proof_data.header_batch.len())
                .unwrap();
        }

        for i in 0..proof_data.header_batch.len() {
            env.write(&proof_data.header_batch[i].version)
                .unwrap()
                .write(&proof_data.header_batch[i].merkle_root.as_raw_hash())
                .unwrap()
                .write(&proof_data.header_batch[i].time)
                .unwrap()
                .write(&proof_data.header_batch[i].bits)
                .unwrap()
                .write(&proof_data.header_batch[i].nonce)
                .unwrap();
        }

        let env = env
            .build()
            .map_err(|e| BridgeError::ProveError(e.to_string()))?;

        let prover = risc0_zkvm::default_prover();

        let receipt = prover
            .prove(env, header_chain_circuit::HEADER_CHAIN_GUEST_ELF)
            .map_err(|e| BridgeError::ProveError(e.to_string()))?
            .receipt;
        let output: ([u32; 8], [u8; 32], u32, [u8; 32], [u8; 32]) = receipt
            .journal
            .decode()
            .map_err(|e| BridgeError::ProveError(e.to_string()))?;

        tracing::debug!("Receipt: {:#?}", receipt);
        tracing::debug!("Decoded journal output: {:?}", output);

        Ok((receipt, output))
    }

    /// Returns active blockchain tip.
    fn get_active_tip(&self) -> Result<GetChainTipsResultTip, BridgeError> {
        let tips = self.rpc.client.get_chain_tips()?;
        let tip = tips
            .iter()
            .find(|tip| tip.status == GetChainTipsResultStatus::Active)
            .ok_or(BridgeError::BlockNotFound)?;

        tracing::trace!(
            "Active blockchain tip is at height {} with block hash {}",
            tip.height,
            tip.hash
        );

        Ok(tip.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chain_prover::{BlockFetchStatus, ChainProver, ProofData, DEEPNESS},
        create_extended_rpc,
        extended_rpc::ExtendedRpc,
        mock::database::create_test_config_with_thread_name,
    };
    use bitcoin::{hashes::Hash, BlockHash, Work};
    use bitcoincore_rpc::RpcApi;
    use risc0_zkvm::Receipt;

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
        let current_tip = prover.get_active_tip().unwrap();
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

    #[tokio::test]
    async fn sync_blockchain() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save current blockchain tip.
        let current_tip = prover.get_active_tip().unwrap();
        let current_block = rpc.client.get_block(&current_tip.hash).unwrap();

        // Update database with current block.
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

        // Falling behind some blocks.
        rpc.mine_blocks(DEEPNESS - 1).unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::FallenBehind(current_tip.height, current_tip.hash)
        );

        // Sync database to current active blockchain.
        prover.sync_blockchain().await.unwrap();
        assert_eq!(
            prover.check_for_new_blocks().await.unwrap(),
            BlockFetchStatus::UpToDate
        );
    }

    #[tokio::test]
    async fn prove_block_genesis() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        let proof_data = ProofData::default();
        let output = prover
            .prove_block(proof_data.clone(), None::<Receipt>)
            .await
            .unwrap();

        assert_eq!(output.1 .0, proof_data.prev_method_id);
        assert_eq!(
            output.1 .1,
            proof_data.genesis_block_hash.as_raw_hash().to_byte_array()
        );
    }

    #[tokio::test]
    async fn prove_block_second_block() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        // Prove genesis block,
        let (receipt, values) = prover
            .prove_block(ProofData::default(), None::<Receipt>)
            .await
            .unwrap();

        // Prove second block
        let hash = rpc.client.get_block_hash(1).unwrap();
        let header = rpc.client.get_block_header(&hash).unwrap();
        let proof_data = ProofData {
            genesis_block_hash: BlockHash::from_raw_hash(Hash::from_slice(&values.1).unwrap()),
            is_genesis: false,
            prev_method_id: values.0,
            prev_offset: values.2,
            prev_block_hash: BlockHash::from_raw_hash(Hash::from_slice(&values.3).unwrap()),
            prev_total_work: Work::from_be_bytes(values.4),
            return_offset: 0,
            header_batch: vec![header],
        };
        let output = prover
            .prove_block(proof_data.clone(), Some(receipt))
            .await
            .unwrap();

        assert_eq!(output.1 .0, proof_data.prev_method_id);
        assert_eq!(
            output.1 .1,
            proof_data.genesis_block_hash.as_raw_hash().to_byte_array()
        );
    }

    #[tokio::test]
    async fn prove_block_current() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        let current_tip = prover.get_active_tip().unwrap();
        let current_block = rpc.client.get_block(&current_tip.hash).unwrap();
        let prev_block_hash = current_block.header.prev_blockhash;
        let proof_data = ProofData {
            genesis_block_hash: prev_block_hash,
            is_genesis: false,
            prev_method_id: [0; 8],
            prev_offset: 0,
            prev_block_hash: current_block.block_hash(),
            prev_total_work: current_block.header.work(),
            return_offset: 0,
            header_batch: vec![],
        };
        let output = prover
            .prove_block(proof_data.clone(), None::<Receipt>)
            .await
            .unwrap();
        assert_eq!(output.1 .0, proof_data.prev_method_id);
    }
}
