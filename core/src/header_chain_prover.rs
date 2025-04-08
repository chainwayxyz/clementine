//! # Header Chain Prover

use crate::database::DatabaseTransaction;
use crate::errors::ResultExt;
use crate::states::block_cache::BlockCache;
use crate::{
    config::BridgeConfig,
    database::Database,
    errors::{BridgeError, ErrorExt},
    extended_rpc::ExtendedRpc,
};
use bitcoin::block::Header;
use bitcoin::{hashes::Hash, BlockHash, Network};
use bitcoincore_rpc::RpcApi;
use eyre::Context;
use lazy_static::lazy_static;
use risc0_to_bitvm2_core::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use risc0_zkvm::{compute_image_id, ExecutorEnv, Receipt};
use std::{
    fs::File,
    io::{BufReader, Read},
};
use thiserror::Error;

// Prepare prover binaries and calculate their image ids, before anything else.
const MAINNET_ELF: &[u8; 199812] = include_bytes!("../../scripts/mainnet-header-chain-guest");
const TESTNET4_ELF: &[u8; 200180] = include_bytes!("../../scripts/testnet4-header-chain-guest");
const SIGNET_ELF: &[u8; 199828] = include_bytes!("../../scripts/signet-header-chain-guest");
const REGTEST_ELF: &[u8; 194128] = include_bytes!("../../scripts/regtest-header-chain-guest");
lazy_static! {
    static ref MAINNET_IMAGE_ID: [u32; 8] = compute_image_id(MAINNET_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
    static ref TESTNET4_IMAGE_ID: [u32; 8] = compute_image_id(TESTNET4_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
    static ref SIGNET_IMAGE_ID: [u32; 8] = compute_image_id(SIGNET_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
    static ref REGTEST_IMAGE_ID: [u32; 8] = compute_image_id(REGTEST_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
}

#[derive(Debug, Error)]
pub enum HeaderChainProverError {
    #[error("Error while de/serializing object")]
    ProverDeSerializationError,
    #[error("No header chain proofs for hash {0}")]
    NoHeaderChainProof(BlockHash),
    #[error("Wait for candidate batch to be ready")]
    BatchNotReady,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, Clone)]
pub struct HeaderChainProver {
    db: Database,
    rpc: ExtendedRpc,
    network: bitcoin::Network,
    batch_size: u64,
}

impl HeaderChainProver {
    pub async fn new(
        config: &BridgeConfig,
        rpc: ExtendedRpc,
    ) -> Result<Self, HeaderChainProverError> {
        let db = Database::new(config).await.map_to_eyre()?;

        if let Some(proof_file) = &config.header_chain_proof_path {
            tracing::info!("Starting prover with assumption file {:?}.", proof_file);
            let file = File::open(proof_file)
                .wrap_err_with(|| format!("Failed to open proof assumption file {proof_file:?}"))?;

            let mut reader = BufReader::new(file);
            let mut assumption = Vec::new();
            reader
                .read_to_end(&mut assumption)
                .wrap_err(BridgeError::BorshError)?; // TODO: Not borsh.

            let proof: Receipt = borsh::from_slice(&assumption)
                .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;
            let proof_output: BlockHeaderCircuitOutput = borsh::from_slice(&proof.journal.bytes)
                .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;

            // Create block entry, if not exists.
            let block_hash = BlockHash::from_raw_hash(
                Hash::from_slice(&proof_output.chain_state.best_block_hash).map_to_eyre()?,
            );
            let block_header = rpc
                .client
                .get_block_header(&block_hash)
                .await
                .wrap_err("Failed to get block header")?;
            let block_height = rpc
                .client
                .get_block_info(&block_hash)
                .await
                .map(|info| info.height)
                .wrap_err("Failed to get block info")?;
            tracing::info!(
                "Adding proof assumption for a block with hash of {:?}, header of {:?} and height of {}",
                block_hash,
                block_header,
                block_height
            );

            // Ignore error if block entry is in database already.
            let _ = db
                .save_unproven_block(
                    None,
                    block_hash,
                    block_header,
                    proof_output.chain_state.block_height.into(),
                )
                .await;

            // Save proof receipt.
            db.set_block_proof(None, block_hash, proof)
                .await
                .map_to_eyre()?;
        };

        Ok(HeaderChainProver {
            db,
            rpc,
            batch_size: config
                .protocol_paramset()
                .header_chain_proof_batch_size
                .into(),
            network: config.protocol_paramset().network,
        })
    }

    /// Proves blocks till the block with hash `current_block_hash`.
    ///
    /// # Parameters
    ///
    /// - `current_block_hash`: Hash of the block to prove
    /// - `block_headers`: Block headers to prove
    /// - `previous_proof`: Previous proof's receipt
    #[tracing::instrument(skip_all)]
    async fn prove_blocks(
        &self,
        current_block_hash: BlockHash,
        block_headers: Vec<Header>,
        previous_proof: Receipt,
    ) -> Result<Receipt, BridgeError> {
        tracing::info!(
            "Prover starts proving {} blocks ending with block with hash {}",
            block_headers.len(),
            current_block_hash
        );

        let headers: Vec<CircuitBlockHeader> = block_headers.into_iter().map(Into::into).collect();
        let receipt = self.prove_block_headers(Some(previous_proof), headers)?;

        self.db
            .set_block_proof(None, current_block_hash, receipt.clone())
            .await?;

        Ok(receipt)
    }

    /// Proves given block headers.
    ///
    /// # Parameters
    ///
    /// - `prev_receipt`: Previous proof's receipt, if not genesis block
    /// - `block_headers`: Block headers to prove
    ///
    /// # Returns
    ///
    /// - [`Receipt`]: Proved block headers' proof receipt.
    fn prove_block_headers(
        &self,
        prev_receipt: Option<Receipt>,
        block_headers: Vec<CircuitBlockHeader>,
    ) -> Result<Receipt, HeaderChainProverError> {
        // Prepare proof input.
        let (prev_proof, method_id) = match &prev_receipt {
            Some(receipt) => {
                let prev_output: BlockHeaderCircuitOutput =
                    borsh::from_slice(&receipt.journal.bytes)
                        .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;
                let method_id = prev_output.method_id;

                (HeaderChainPrevProofType::PrevProof(prev_output), method_id)
            }
            None => {
                let image_id = match self.network {
                    Network::Bitcoin => *MAINNET_IMAGE_ID,
                    Network::Testnet => *TESTNET4_IMAGE_ID,
                    Network::Testnet4 => *TESTNET4_IMAGE_ID,
                    Network::Signet => *SIGNET_IMAGE_ID,
                    Network::Regtest => *REGTEST_IMAGE_ID,
                    _ => Err(BridgeError::UnsupportedNetwork.into_eyre())?,
                };

                (HeaderChainPrevProofType::GenesisBlock, image_id)
            }
        };
        let input = HeaderChainCircuitInput {
            method_id,
            prev_proof,
            block_headers,
        };

        let mut env = ExecutorEnv::builder();

        env.write_slice(&borsh::to_vec(&input).wrap_err(BridgeError::BorshError)?);

        if let Some(prev_receipt) = prev_receipt {
            env.add_assumption(prev_receipt);
        }

        let env = env
            .build()
            .map_err(|e| eyre::eyre!(e))
            .wrap_err("Failed to build environment")?;

        let prover = risc0_zkvm::default_prover();

        let elf = match self.network {
            Network::Bitcoin => MAINNET_ELF.as_ref(),
            Network::Testnet => TESTNET4_ELF.as_ref(),
            Network::Testnet4 => TESTNET4_ELF.as_ref(),
            Network::Signet => SIGNET_ELF.as_ref(),
            Network::Regtest => REGTEST_ELF.as_ref(),
            _ => Err(BridgeError::UnsupportedNetwork.into_eyre())?,
        };

        let receipt = prover.prove(env, elf).map_err(|e| eyre::eyre!(e))?.receipt;
        tracing::debug!(
            "Proof receipt for header chain circuit input {:?}: {:?}",
            input,
            receipt
        );

        Ok(receipt)
    }

    /// Get the proof of a block.
    ///
    /// # Parameters
    ///
    /// - `hash`: Target block hash
    ///
    /// # Returns
    ///
    /// - [`Receipt`]: Specified block's proof receipt
    pub async fn get_header_chain_proof(&self, hash: BlockHash) -> Result<Receipt, BridgeError> {
        // Return cached proof if exists.
        if let Some(proof) = self
            .db
            .get_block_proof_by_hash(None, hash)
            .await
            .wrap_err("Failed to get block proof")?
        {
            return Ok(proof);
        }

        let latest_proven_block = self
            .db
            .get_latest_proven_block_info(None)
            .await?
            .ok_or(eyre::eyre!("No proven block found"))?;
        let tip_height = self
            .rpc
            .client
            .get_block_count()
            .await
            .wrap_err("Can't get block tip height")?;

        if tip_height - latest_proven_block.2 > self.batch_size
            && tip_height - latest_proven_block.2 == self.batch_size
        {
            return Err(HeaderChainProverError::BatchNotReady.into());
        }

        // If in limits of the batch size but not in a target block, prove block
        // headers manually.
        let mut block_headers = Vec::new();
        for i in latest_proven_block.2..tip_height {
            let block_hash = self
                .rpc
                .client
                .get_block_hash(i)
                .await
                .wrap_err("Failed to get block hash")?;
            let block_header = self
                .rpc
                .client
                .get_block_header(&block_hash)
                .await
                .wrap_err("Failed to get block header")?;

            block_headers.push(block_header);
        }

        let previous_proof = self
            .db
            .get_block_proof_by_hash(None, latest_proven_block.0)
            .await?
            .ok_or(eyre::eyre!("No proven block found"))?;
        let receipt = self
            .prove_blocks(hash, block_headers, previous_proof)
            .await?;

        Ok(receipt)
    }

    /// Saves a new block to database, later to be proven.
    pub async fn save_unproven_block_cache(
        &self,
        dbtx: Option<DatabaseTransaction<'_, '_>>,
        block_cache: &BlockCache,
    ) -> Result<(), BridgeError> {
        let block_hash = block_cache
            .block
            .as_ref()
            .ok_or(eyre::eyre!("Block not found"))?
            .block_hash();

        let block_header = block_cache
            .block
            .as_ref()
            .ok_or(eyre::eyre!("Block not found"))?
            .header;

        self.db
            .save_unproven_block(
                dbtx,
                block_hash,
                block_header,
                block_cache.block_height.into(),
            )
            .await?;

        Ok(())
    }

    /// Checks if there are enough blocks to prove.
    #[tracing::instrument(skip_all)]
    async fn is_batch_ready(&self) -> Result<bool, BridgeError> {
        let non_proven_block = if let Some(block) = self.db.get_next_non_proven_block(None).await? {
            block
        } else {
            return Ok(false);
        };
        let tip_height = self
            .db
            .get_latest_block_height(None)
            .await?
            .ok_or(eyre::eyre!("No tip block found"))?;

        tracing::debug!(
            "Tip height: {}, non proven block height: {}, {}",
            tip_height,
            non_proven_block.2,
            self.batch_size
        );
        if tip_height - non_proven_block.2 >= self.batch_size {
            return Ok(true);
        }
        tracing::debug!(
            "Batch not ready: {} - {} < {}",
            tip_height,
            non_proven_block.2,
            self.batch_size
        );

        Ok(false)
    }

    pub async fn prove_if_ready(&self) -> Result<Option<Receipt>, BridgeError> {
        if !self.is_batch_ready().await? {
            return Ok(None);
        }

        let unproven_blocks = self
            .db
            .get_next_n_non_proven_block(
                self.batch_size
                    .try_into()
                    .wrap_err("Can't convert u64 to u32")?,
            )
            .await?;
        let (unproven_blocks, prev_proof) = match unproven_blocks {
            Some(unproven_blocks) => unproven_blocks,
            None => {
                tracing::debug!("No unproven blocks found");
                return Ok(None);
            }
        };

        let current_block_hash = unproven_blocks.iter().next_back().expect("Exists").0;
        let current_block_height = unproven_blocks.iter().next_back().expect("Exists").2;
        let block_headers = unproven_blocks
            .iter()
            .map(|(_, header, _)| *header)
            .collect::<Vec<_>>();

        let receipt = self
            .prove_blocks(current_block_hash, block_headers, prev_proof)
            .await?;
        tracing::info!(
            "Receipt for block with hash {:?} and height with: {:?}: {:?}",
            current_block_hash,
            current_block_height,
            receipt
        );

        Ok(Some(receipt))
    }
}

#[cfg(test)]
mod tests {
    use crate::citrea::mock::MockCitreaClient;
    use crate::database::Database;
    use crate::extended_rpc::ExtendedRpc;
    use crate::header_chain_prover::HeaderChainProver;
    use crate::test::common::*;
    use crate::verifier::VerifierServer;
    use bitcoin::{block::Header, hashes::Hash, BlockHash};
    use bitcoincore_rpc::RpcApi;
    use borsh::BorshDeserialize;
    use risc0_to_bitvm2_core::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
    use risc0_zkvm::Receipt;

    /// Mines `block_num` amount of blocks (if not already mined) and returns
    /// the first `block_num` block headers in blockchain.
    async fn mine_and_get_first_n_block_headers(
        rpc: ExtendedRpc,
        db: Database,
        block_num: u64,
    ) -> Vec<Header> {
        let height = rpc.client.get_block_count().await.unwrap();
        tracing::debug!(
            "Current tip height: {}, target block height: {}",
            height,
            block_num
        );
        if height < block_num {
            tracing::debug!(
                "Mining {} blocks to reach block number {}",
                block_num - height,
                block_num
            );
            rpc.mine_blocks(block_num - height + 1).await.unwrap();
        }

        tracing::debug!("Getting first {} block headers from blockchain", block_num);
        let mut headers = Vec::new();
        for i in 0..block_num + 1 {
            let hash = rpc.client.get_block_hash(i).await.unwrap();
            let header = rpc.client.get_block_header(&hash).await.unwrap();

            headers.push(header);

            let _ignore_errors = db.save_unproven_block(None, hash, header, i).await;
        }

        headers
    }

    #[tokio::test]
    async fn new() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let _should_not_panic = HeaderChainProver::new(&config, rpc).await.unwrap();
    }

    #[tokio::test]
    async fn new_with_proof_assumption() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        // First block's assumption will be added to db: Make sure block exists
        // too.
        rpc.mine_blocks(1).await.unwrap();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        // Test assumption is for block 0.
        let hash = rpc.client.get_block_hash(0).await.unwrap();
        let _should_not_panic = prover.get_header_chain_proof(hash).await.unwrap();

        let wrong_hash = BlockHash::from_raw_hash(Hash::from_slice(&[0x45; 32]).unwrap());
        assert_ne!(wrong_hash, hash);
        assert!(prover.get_header_chain_proof(wrong_hash).await.is_err());
    }

    #[tokio::test]
    async fn prove_a_block_from_database() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        // Check if `HeaderChainProver::new` added the assumption.
        let previous_receipt =
            Receipt::try_from_slice(include_bytes!("../tests/data/first_1.bin")).unwrap();
        let height = 0;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let read_recipt = prover.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(previous_receipt.journal, read_recipt.journal);

        // Set up the next non proven block.
        let height = 1;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let block = rpc.client.get_block(&hash).await.unwrap();
        let header = block.header;
        prover
            .db
            .save_unproven_block(None, hash, header, height)
            .await
            .unwrap();

        let receipt = prover
            .prove_blocks(hash, vec![header], previous_receipt)
            .await
            .unwrap();

        let read_recipt = prover.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(receipt.journal, read_recipt.journal);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prove_block_headers_genesis() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        let receipt = prover.prove_block_headers(None, vec![]).unwrap();

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
    async fn prove_block_headers_second() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        // Prove genesis block and get it's receipt.
        let receipt = prover.prove_block_headers(None, vec![]).unwrap();

        let block_headers = mine_and_get_first_n_block_headers(rpc, prover.db.clone(), 3)
            .await
            .iter()
            .map(|header| CircuitBlockHeader::from(*header))
            .collect::<Vec<_>>();
        let receipt = prover
            .prove_block_headers(Some(receipt), block_headers[0..2].to_vec())
            .unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();

        println!("Proof journal output: {:?}", output);

        assert_eq!(output.chain_state.block_height, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn is_batch_ready() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        let genesis_hash = rpc.client.get_block_hash(0).await.unwrap();
        let genesis_block_proof = prover.get_header_chain_proof(genesis_hash).await.unwrap();
        let db_proof = db
            .get_block_proof_by_hash(None, genesis_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(genesis_block_proof.journal, db_proof.journal);

        // TODO: Non proven block check returns an error instead of None. Later remove these lines
        let block_height = 1;
        let block_hash = rpc.client.get_block_hash(block_height).await.unwrap();
        let block_header = rpc.client.get_block_header(&block_hash).await.unwrap();
        db.save_unproven_block(None, block_hash, block_header, block_height)
            .await
            .unwrap();

        // Batch can't be ready because there are less than `batch_size` blocks
        // between non-proven tip and last proven block
        assert!(!prover.is_batch_ready().await.unwrap());

        // Mining required amount of blocks should make batch proving ready.
        let _headers = mine_and_get_first_n_block_headers(
            rpc.clone(),
            db,
            block_height + batch_size as u64 + 1,
        )
        .await;
        assert!(prover.is_batch_ready().await.unwrap());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prove_if_ready() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save some initial blocks.
        mine_and_get_first_n_block_headers(rpc.clone(), db.clone(), 2).await;

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        assert!(prover.prove_if_ready().await.unwrap().is_none());

        let latest_proven_block_height =
            db.get_next_non_proven_block(None).await.unwrap().unwrap().2;
        let _block_headers = mine_and_get_first_n_block_headers(
            rpc.clone(),
            db.clone(),
            (latest_proven_block_height + batch_size as u64).into(),
        )
        .await;

        let receipt = prover.prove_if_ready().await.unwrap().unwrap();
        let latest_proof = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        let get_receipt = prover.get_header_chain_proof(latest_proof.0).await.unwrap();
        assert_eq!(receipt.journal, get_receipt.journal);
        assert_eq!(receipt.metadata, get_receipt.metadata);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prove_and_get_non_targeted_block() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save some initial blocks.
        mine_and_get_first_n_block_headers(rpc.clone(), db.clone(), 2).await;

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        assert!(prover.prove_if_ready().await.unwrap().is_none());

        let latest_proven_block_height =
            db.get_next_non_proven_block(None).await.unwrap().unwrap().2;
        let _block_headers = mine_and_get_first_n_block_headers(
            rpc.clone(),
            db.clone(),
            (latest_proven_block_height + batch_size as u64).into(),
        )
        .await;

        let receipt = prover.prove_if_ready().await.unwrap().unwrap();
        let latest_proof = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        let get_receipt = prover.get_header_chain_proof(latest_proof.0).await.unwrap();
        assert_eq!(receipt.journal, get_receipt.journal);
        assert_eq!(receipt.metadata, get_receipt.metadata);

        // Try to get proof of the previous block that its heir is proven.
        let target_height = latest_proof.2 - 1;
        let target_hash = rpc.client.get_block_hash(target_height).await.unwrap();

        assert!(db
            .get_block_proof_by_hash(None, target_hash)
            .await
            .unwrap()
            .is_none());

        // get_header_chain_proof should calculate the proof for the block.
        let _receipt = prover.get_header_chain_proof(target_hash).await.unwrap();
    }

    #[tokio::test]
    async fn verifier_new_check_header_chain_proof() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        // Save initial blocks, because VerifierServer won't.
        let count = rpc.client.get_block_count().await.unwrap();
        tracing::info!("Block count: {}", count);
        for i in 1..count + 1 {
            let hash = rpc.client.get_block_hash(i).await.unwrap();
            let block = rpc.client.get_block(&hash).await.unwrap();

            db.save_unproven_block(None, block.block_hash(), block.header, i)
                .await
                .unwrap();
        }

        let verifier = VerifierServer::<MockCitreaClient>::new(config)
            .await
            .unwrap();
        // Make sure enough blocks to prove and is confirmed.
        rpc.mine_blocks((batch_size + 10).into()).await.unwrap();

        // Aim for a proved block that is added to the database by the verifier.
        let height = batch_size;
        let hash = rpc.client.get_block_hash(height.into()).await.unwrap();

        poll_until_condition(
            async || {
                Ok(verifier
                    .verifier
                    .header_chain_prover
                    .get_header_chain_proof(hash)
                    .await
                    .is_ok())
            },
            None,
            None,
        )
        .await
        .unwrap();
    }
}
