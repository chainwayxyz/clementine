//! # Header Chain Prover
//!
//! Fetches latest blocks from Bitcoin and prepares proves for them.

use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError, extended_rpc::ExtendedRpc,
};
use bitcoin::{hashes::Hash, BlockHash};
use bitcoin_mock_rpc::RpcApiWrapper;
use circuits::header_chain::{
    BlockHeader, BlockHeaderCircuitOutput, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use risc0_zkvm::{compute_image_id, ExecutorEnv, Receipt};
use std::{
    fs::File,
    io::{BufReader, Read},
    time::Duration,
};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    time::sleep,
};

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
    /// Current saved tip (with `difference` specified) is too far behind the actual tip.
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

        if let Some(proof_file) = &config.header_chain_proof {
            let file = File::open(proof_file).map_err(|e| {
                BridgeError::ProveError(format!(
                    "Can't read assumption file {:?} with error {}",
                    proof_file, e
                ))
            })?;
            let mut reader = BufReader::new(file);
            let mut assumption = Vec::new();
            reader.read_to_end(&mut assumption)?;

            let proof: Receipt = borsh::from_slice(&assumption).map_err(|e| {
                BridgeError::ProveError(format!("Proof assumption is malformed: {}", e))
            })?;
            let prev_output: BlockHeaderCircuitOutput = borsh::from_slice(&proof.journal.bytes)
                .map_err(|e| {
                    BridgeError::ProveError(format!("Can't convert journal to bytes: {}", e))
                })?;

            // Create block entry, if not exists.
            let block_hash = rpc
                .client
                .get_block_hash(prev_output.chain_state.block_height.into())?;
            let block_header = rpc.client.get_block_header(&block_hash)?;
            // Ignore error if block entry is in database already.
            let _ = db
                .save_new_block(
                    None,
                    block_hash,
                    block_header,
                    prev_output.chain_state.block_height.into(),
                )
                .await;

            // Save proof assumption.
            db.save_block_proof(None, block_hash, proof).await?;
        };

        Ok(ChainProver { rpc, db })
    }

    /// Get the proof of a block.
    ///
    /// # Parameters
    ///
    /// - `hash`: Target block hash
    pub async fn get_header_chain_proof(&self, hash: BlockHash) -> Result<Receipt, BridgeError> {
        match self.db.get_block_proof_by_hash(None, hash).await? {
            Some(r) => Ok(r),
            None => Err(BridgeError::ProveError(format!(
                "No proof is present for block with block hash {}",
                hash
            ))),
        }
    }

    /// Starts a background task that syncs current database to active
    /// blockchain and does proving.
    #[tracing::instrument]
    pub fn start_header_chain_prover(&self) {
        let (tx, rx) = mpsc::channel::<()>(5);

        // Block checks.
        let block_checks = ChainProver {
            rpc: self.rpc.clone(),
            db: self.db.clone(),
        };
        let block_gazer = ChainProver::start_blockgazer(block_checks, tx);

        // Prover.
        let prover = ChainProver {
            rpc: self.rpc.clone(),
            db: self.db.clone(),
        };
        let prover = ChainProver::start_prover(prover, rx);

        tokio::spawn(async move {
            tokio::join!(block_gazer, prover);
        });
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

        let tip_height = self.rpc.client.get_block_count()?;
        let tip_hash = self.rpc.client.get_block_hash(tip_height)?;
        let tip_prev_blockhash = self.rpc.client.get_block_header(&tip_hash)?.prev_blockhash;
        tracing::trace!(
            "Active blockchain tip is at height {} with block hash {}",
            tip_height,
            tip_hash
        );

        // Return early if database is up to date. Or if hash is not matching,
        // possible reorg might have happened.
        if db_tip_height == tip_height && db_tip_hash == tip_hash {
            tracing::debug!("Database is in sync with active blockchain.");

            return Ok(BlockFetchStatus::UpToDate);
        } else if (db_tip_height == tip_height && db_tip_hash != tip_hash)
            || (db_tip_height > tip_height)
        {
            tracing::error!("Current database blockchain tip is not on branch with the active blockchain (possible reorg)!");

            return Ok(BlockFetchStatus::Fork(db_tip_height, db_tip_hash));
        }

        // Return height difference if actual tip is too far behind.
        let diff = tip_height - db_tip_height;
        if diff > DEEPNESS {
            tracing::error!(
                "Current tip is fallen too far behind (difference is {} blocks)!",
                diff
            );

            return Ok(BlockFetchStatus::OutOfBounds(diff));
        }

        // Go back block by block to check that we are still at the same branch
        // as the active blockchain.
        let mut previous_block_hash = tip_prev_blockhash;
        for deepness in 1..DEEPNESS + 1 {
            let current_block = self.rpc.client.get_block(&previous_block_hash)?;
            let current_block_hash = previous_block_hash;
            previous_block_hash = current_block.header.prev_blockhash;

            let db_block_hash = match self
                .db
                .get_block_proof_info_by_height(None, tip_height.wrapping_sub(deepness))
                .await
            {
                Ok(r) => r.0,
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

        tracing::error!("Current database blockchain tip is not on branch with the active blockchain (possible reorg)!");

        Ok(BlockFetchStatus::Fork(db_tip_height, db_tip_hash))
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
    async fn start_blockgazer(prover: ChainProver<R>, tx: Sender<()>)
    where
        R: RpcApiWrapper,
    {
        loop {
            if let Ok(status) = prover.check_for_new_blocks().await {
                match status {
                    BlockFetchStatus::UpToDate => (),
                    BlockFetchStatus::FallenBehind(block_height, _block_hash) => {
                        prover.sync_blockchain(block_height).await.unwrap();
                        tx.send(()).await.unwrap();
                    }
                    _ => panic!("Hapi yuttun"),
                }
            };

            sleep(Duration::from_millis(1000)).await;
        }
    }

    /// Prove a block.
    ///
    /// # Parameters
    ///
    /// - `prev_receipt`: Some previous run's receipt, if not genesis block
    /// - `block_headers`: Block headers to prove
    ///
    /// # Returns
    ///
    /// - [`Receipt`]: Proved block's proof receipt.
    async fn prove_block(
        &self,
        prev_receipt: Option<Receipt>,
        block_headers: Vec<BlockHeader>,
    ) -> Result<Receipt, BridgeError> {
        // Prepare prover binary.
        const ELF: &[u8; 186232] = include_bytes!("../../scripts/header-chain-guest");
        let image_id: [u32; 8] = compute_image_id(ELF)
            .map_err(|e| BridgeError::ProveError(format!("Can't compute image id: {}", e)))?
            .as_words()
            .try_into()
            .map_err(|e| {
                BridgeError::ProveError(format!(
                    "Can't convert computed image id to [u32; 8]: {}",
                    e
                ))
            })?;

        // Prepare proof input.
        let (prev_proof, method_id) = match &prev_receipt {
            Some(receipt) => {
                let prev_output: BlockHeaderCircuitOutput =
                    borsh::from_slice(&receipt.journal.bytes).map_err(|e| {
                        BridgeError::ProveError(format!("Can't convert journal to bytes: {}", e))
                    })?;
                let method_id = prev_output.method_id;

                (HeaderChainPrevProofType::PrevProof(prev_output), method_id)
            }
            None => (HeaderChainPrevProofType::GenesisBlock, image_id),
        };
        let input = HeaderChainCircuitInput {
            method_id,
            prev_proof,
            block_headers,
        };

        let mut env = ExecutorEnv::builder();

        env.write_slice(&borsh::to_vec(&input)?);

        if let Some(prev_receipt) = prev_receipt {
            env.add_assumption(prev_receipt);
        }

        let env = env
            .build()
            .map_err(|e| BridgeError::ProveError(e.to_string()))?;

        let prover = risc0_zkvm::default_prover();

        tracing::trace!("Proving started for block");
        let receipt = prover
            .prove(env, ELF)
            .map_err(|e| BridgeError::ProveError(e.to_string()))?
            .receipt;

        tracing::debug!("Proof receipt: {:?}", receipt);

        Ok(receipt)
    }

    /// Starts a Tokio task that proves new blocks.
    ///
    /// # Parameters
    ///
    /// - prover: [`ChainProver`] instance
    /// - rx: Receiver end for blockgazer
    #[tracing::instrument(skip_all)]
    async fn start_prover(prover: ChainProver<R>, mut rx: Receiver<()>) {
        loop {
            // Prover waits for blockgazer's notification for new blocks
            // before doing any proving.
            rx.recv().await;

            let non_proved_block = prover.db.get_non_proven_block(None).await;

            if let Ok((
                current_block_hash,
                current_block_header,
                _current_block_height,
                previous_proof,
            )) = non_proved_block
            {
                tracing::trace!(
                    "Prover starts proving for block with hash: {}",
                    current_block_hash
                );

                let header = BlockHeader {
                    version: current_block_header.version.to_consensus(),
                    prev_block_hash: current_block_header.prev_blockhash.to_byte_array(),
                    merkle_root: current_block_header.merkle_root.to_byte_array(),
                    time: current_block_header.time,
                    bits: current_block_header.bits.to_consensus(),
                    nonce: current_block_header.nonce,
                };
                let receipt = prover.prove_block(Some(previous_proof), vec![header]).await;

                if let Ok(receipt) = receipt {
                    prover
                        .db
                        .save_block_proof(None, current_block_hash, receipt)
                        .await
                        .unwrap();

                    // Only continue to check for new unproven blocks, if
                    // this attempt was successful.
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        create_extended_rpc,
        extended_rpc::ExtendedRpc,
        header_chain_prover::{BlockFetchStatus, ChainProver, DEEPNESS},
        mock::database::create_test_config_with_thread_name,
    };
    use bitcoin::{
        block::{Header, Version},
        hashes::Hash,
        BlockHash, CompactTarget, TxMerkleNode,
    };
    use bitcoincore_rpc::RpcApi;
    use borsh::BorshDeserialize;
    use circuits::header_chain::{BlockHeader, BlockHeaderCircuitOutput};
    use risc0_zkvm::Receipt;
    use std::time::Duration;
    use tokio::time::sleep;

    fn get_headers() -> Vec<BlockHeader> {
        let headers = include_bytes!("../../scripts/headers.bin");

        headers
            .chunks(80)
            .map(|header| BlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<BlockHeader>>()
    }

    #[tokio::test]
    async fn new() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);

        let _should_not_panic = ChainProver::new(&config, rpc).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn new_with_proof_assumption() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);

        // First block's assumption will be added to db: Make sure block exists
        // too.
        rpc.mine_blocks(1).unwrap();

        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        // Test assumption is for block 0.
        let hash = rpc.client.get_block_hash(0).unwrap();
        let _should_not_panic = prover.get_header_chain_proof(hash).await.unwrap();

        let wrong_hash = BlockHash::from_raw_hash(Hash::from_slice(&[0x45; 32]).unwrap());
        assert_ne!(wrong_hash, hash);
        assert!(prover.get_header_chain_proof(wrong_hash).await.is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_uptodate() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

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
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

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
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

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
    async fn sync_blockchain() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

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

    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "Proving takes too much time: Only run it when it's necessary"]
    async fn prove_block_genesis() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        let receipt = prover.prove_block(None, vec![]).await.unwrap();

        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        println!("Proof journal output: {:?}", output);

        assert_eq!(output.chain_state.block_height, u32::MAX); // risc0-to-bitvm2 related
        assert_eq!(
            output.chain_state.best_block_hash,
            BlockHash::all_zeros().as_raw_hash().to_byte_array()
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "Proving takes too much time: Only run it when it's necessary"]
    async fn prove_block_second() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        // Prove genesis block and get it's receipt.
        let receipt = prover.prove_block(None, vec![]).await.unwrap();

        let block_headers = get_headers();
        let receipt = prover
            .prove_block(Some(receipt), block_headers[0..2].to_vec())
            .await
            .unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();

        println!("Proof journal output: {:?}", output);

        assert_eq!(output.chain_state.block_height, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "Proving takes too much time: Only run it when it's necessary"]
    async fn save_and_get_proof() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();
        let block_headers = get_headers();

        // Prove genesis block.
        let receipt = prover.prove_block(None, vec![]).await.unwrap();
        let hash =
            BlockHash::from_raw_hash(Hash::from_slice(&block_headers[0].prev_block_hash).unwrap());
        let header = Header {
            version: Version::from_consensus(block_headers[0].version),
            prev_blockhash: BlockHash::from_raw_hash(Hash::from_byte_array(
                block_headers[0].prev_block_hash,
            )),
            merkle_root: TxMerkleNode::from_raw_hash(Hash::from_byte_array(
                block_headers[0].merkle_root,
            )),
            time: block_headers[0].time,
            bits: CompactTarget::from_consensus(block_headers[0].bits),
            nonce: block_headers[0].nonce,
        };
        prover
            .db
            .save_new_block(None, hash, header, 0)
            .await
            .unwrap();
        prover
            .db
            .save_block_proof(None, hash, receipt.clone())
            .await
            .unwrap();
        let database_receipt = prover.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(receipt.journal, database_receipt.journal);
        assert_eq!(receipt.metadata, database_receipt.metadata);

        // Prove second block.
        let receipt = prover
            .prove_block(Some(receipt), block_headers[0..2].to_vec())
            .await
            .unwrap();
        let hash =
            BlockHash::from_raw_hash(Hash::from_slice(&block_headers[1].prev_block_hash).unwrap());
        let header = Header {
            version: Version::from_consensus(block_headers[1].version),
            prev_blockhash: BlockHash::from_raw_hash(Hash::from_byte_array(
                block_headers[1].prev_block_hash,
            )),
            merkle_root: TxMerkleNode::from_raw_hash(Hash::from_byte_array(
                block_headers[1].merkle_root,
            )),
            time: block_headers[1].time,
            bits: CompactTarget::from_consensus(block_headers[1].bits),
            nonce: block_headers[1].nonce,
        };
        prover
            .db
            .save_new_block(None, hash, header, 0)
            .await
            .unwrap();

        prover
            .db
            .save_block_proof(None, hash, receipt.clone())
            .await
            .unwrap();
        let database_receipt2 = prover.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(receipt.journal, database_receipt2.journal);
        assert_eq!(receipt.metadata, database_receipt2.metadata);
        assert_ne!(receipt.journal, database_receipt.journal);
    }

    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "This test is very host dependent and must need a human observer"]
    async fn start_header_chain_prover() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = ChainProver::new(&config, rpc.clone()).await.unwrap();

        prover.start_header_chain_prover();
        sleep(Duration::from_millis(1000)).await;

        // Mine a block and write genesis block's proof to database.
        rpc.mine_blocks(1).unwrap();
        let receipt = Receipt::try_from_slice(include_bytes!("../tests/data/first_1.bin")).unwrap();
        prover
            .db
            .save_block_proof(None, BlockHash::all_zeros(), receipt.clone())
            .await
            .unwrap();

        let hash = rpc.client.get_block_hash(1).unwrap();
        loop {
            if let Ok(proof) = prover.get_header_chain_proof(hash).await {
                println!("Second block's proof is {:?}", proof);
                break;
            }

            println!("Waiting for proof to be written to database for second block...");
            sleep(Duration::from_millis(1000)).await;
        }
    }
}
