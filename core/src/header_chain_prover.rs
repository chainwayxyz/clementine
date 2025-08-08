//! # Header Chain Prover
//!
//! This module contains utilities for proving Bitcoin block headers. This
//! module must be fed with new blocks via the database. Later, it can check if
//! proving should be triggered by verifying if the batch size is sufficient.

use crate::builder::block_cache::BlockCache;
use crate::database::DatabaseTransaction;
use crate::errors::ResultExt;
use crate::{
    config::BridgeConfig,
    database::Database,
    errors::{BridgeError, ErrorExt},
    extended_rpc::ExtendedRpc,
};
use bitcoin::block::Header;
use bitcoin::{hashes::Hash, BlockHash, Network};
use bitcoincore_rpc::RpcApi;
use bridge_circuit_host::bridge_circuit_host::{
    MAINNET_HEADER_CHAIN_ELF, MAINNET_WORK_ONLY_ELF, REGTEST_HEADER_CHAIN_ELF,
    REGTEST_WORK_ONLY_ELF, SIGNET_HEADER_CHAIN_ELF, SIGNET_WORK_ONLY_ELF,
    TESTNET4_HEADER_CHAIN_ELF, TESTNET4_WORK_ONLY_ELF,
};
use bridge_circuit_host::docker::dev_stark_to_risc0_g16;
use bridge_circuit_host::utils::is_dev_mode;
use circuits_lib::bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput};
use circuits_lib::header_chain::mmr_guest::MMRGuest;
use circuits_lib::header_chain::{
    BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader, HeaderChainCircuitInput,
    HeaderChainPrevProofType,
};
use eyre::{eyre, Context, OptionExt};
use lazy_static::lazy_static;
use risc0_zkvm::{compute_image_id, ExecutorEnv, ProverOpts, Receipt};
use std::{
    fs::File,
    io::{BufReader, Read},
};
use thiserror::Error;

lazy_static! {
    static ref MAINNET_IMAGE_ID: [u32; 8] = compute_image_id(MAINNET_HEADER_CHAIN_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
    static ref TESTNET4_IMAGE_ID: [u32; 8] = compute_image_id(TESTNET4_HEADER_CHAIN_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
    static ref SIGNET_IMAGE_ID: [u32; 8] = compute_image_id(SIGNET_HEADER_CHAIN_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
    static ref REGTEST_IMAGE_ID: [u32; 8] = compute_image_id(REGTEST_HEADER_CHAIN_ELF)
        .expect("hardcoded ELF is valid")
        .as_words()
        .try_into()
        .expect("hardcoded ELF is valid");
}

#[derive(Debug, Error)]
pub enum HeaderChainProverError {
    #[error("Error while de/serializing object")]
    ProverDeSerializationError,
    #[error("Wait for candidate batch to be ready")]
    BatchNotReady,
    #[error("Header chain prover not initialized due to config")]
    HeaderChainProverNotInitialized,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, Clone)]
pub struct HeaderChainProver {
    db: Database,
    network: bitcoin::Network,
    batch_size: u64,
}

impl HeaderChainProver {
    /// Creates a new [`HeaderChainProver`] instance. Also saves a proof
    /// assumption if specified in the config.
    pub async fn new(
        config: &BridgeConfig,
        rpc: ExtendedRpc,
    ) -> Result<Self, HeaderChainProverError> {
        let db = Database::new(config).await.map_to_eyre()?;
        let tip_height = rpc.get_current_chain_height().await.map_to_eyre()?;
        if tip_height
            < config.protocol_paramset().start_height + config.protocol_paramset().finality_depth
        {
            return Err(eyre::eyre!(
                "Start height is not finalized, reduce start height: {} < {}",
                tip_height,
                config.protocol_paramset().start_height + config.protocol_paramset().finality_depth
            )
            .into());
        }
        db.fetch_and_save_missing_blocks(
            &rpc,
            config.protocol_paramset().genesis_height,
            config.protocol_paramset().start_height,
        )
        .await
        .wrap_err("Failed to save initial block infos")?;

        if let Some(proof_file) = &config.header_chain_proof_path {
            tracing::info!("Starting prover with assumption file {:?}.", proof_file);
            let file = File::open(proof_file)
                .wrap_err_with(|| format!("Failed to open proof assumption file {proof_file:?}"))?;

            let mut reader = BufReader::new(file);
            let mut assumption = Vec::new();
            reader
                .read_to_end(&mut assumption)
                .wrap_err("Can't read assumption file")?;

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
                .wrap_err(format!(
                "Failed to get block header with block hash {} (retrieved from assumption file)",
                block_hash
            ))?;
            let block_height = rpc
                .client
                .get_block_info(&block_hash)
                .await
                .map(|info| info.height)
                .wrap_err(format!(
                    "Failed to get block info with block hash {} (retrieved from assumption file)",
                    block_hash
                ))?;
            tracing::info!(
                "Adding proof assumption for a block with hash of {:?}, header of {:?} and height of {}",
                block_hash,
                block_header,
                block_height
            );

            // If an unproven block in database already exists, it shouldn't
            // effect anything.
            // PS: This also ignores other db errors but there are other places
            // where we check for those errors.
            let _ = db
                .save_unproven_finalized_block(
                    None,
                    block_hash,
                    block_header,
                    proof_output.chain_state.block_height.into(),
                )
                .await
                .inspect_err(|e| {
                    tracing::debug!("Can't set initial block info for header chain prover, because: {e}. Doesn't affect anything, continuing...");
                });

            db.set_block_proof(None, block_hash, proof)
                .await
                .map_to_eyre()?;
        } else {
            tracing::info!("Starting prover without assumption, proving genesis block");

            let genesis_block_hash = rpc
                .client
                .get_block_hash(config.protocol_paramset().genesis_height.into())
                .await
                .wrap_err(format!(
                    "Failed to get genesis block hash at height {}",
                    config.protocol_paramset().genesis_height
                ))?;

            tracing::debug!(
                "Genesis block hash: {}, height: {}",
                genesis_block_hash,
                config.protocol_paramset().genesis_height
            ); // Should be debug

            let genesis_block_header = rpc
                .client
                .get_block_header(&genesis_block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get genesis block header at height {}",
                    config.protocol_paramset().genesis_height
                ))?;

            let genesis_chain_state = HeaderChainProver::get_chain_state_from_height(
                rpc.clone(),
                config.protocol_paramset().genesis_height.into(),
                config.protocol_paramset().network,
            )
            .await
            .map_to_eyre()?;
            tracing::debug!("Genesis chain state (verbose): {:?}", genesis_chain_state);

            let genesis_chain_state_hash = genesis_chain_state.to_hash();
            if genesis_chain_state_hash != config.protocol_paramset().genesis_chain_state_hash {
                return Err(eyre::eyre!(
                    "Genesis chain state hash mismatch: {} != {}",
                    hex::encode(genesis_chain_state_hash),
                    hex::encode(config.protocol_paramset().genesis_chain_state_hash)
                )
                .into());
            }

            let proof = HeaderChainProver::prove_genesis_block(
                genesis_chain_state,
                config.protocol_paramset().network,
            )
            .map_to_eyre()?;

            let _ = db
                .save_unproven_finalized_block(
                    None,
                    genesis_block_hash,
                    genesis_block_header,
                    config.protocol_paramset().genesis_height.into(),
                )
                .await;

            db.set_block_proof(None, genesis_block_hash, proof)
                .await
                .map_to_eyre()?;
        }

        Ok(HeaderChainProver {
            db,
            batch_size: config
                .protocol_paramset()
                .header_chain_proof_batch_size
                .into(),
            network: config.protocol_paramset().network,
        })
    }

    pub async fn get_chain_state_from_height(
        rpc: ExtendedRpc,
        height: u64,
        network: Network,
    ) -> Result<ChainState, HeaderChainProverError> {
        let block_hash = rpc
            .client
            .get_block_hash(height)
            .await
            .wrap_err(format!("Failed to get block hash at height {}", height))?;

        let block_header = rpc
            .client
            .get_block_header(&block_hash)
            .await
            .wrap_err(format!(
                "Failed to get block header with block hash {}",
                block_hash
            ))?;

        let mut last_11_block_timestamps: [u32; 11] = [0; 11];
        let mut last_block_hash = block_hash;
        let mut last_block_height = height;
        for _ in 0..11 {
            let block_header = rpc
                .client
                .get_block_header(&last_block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block header with block hash {}",
                    last_block_hash
                ))?;

            last_11_block_timestamps[last_block_height as usize % 11] = block_header.time;

            last_block_hash = block_header.prev_blockhash;
            last_block_height = last_block_height.wrapping_sub(1);

            if last_block_hash.to_byte_array() == [0u8; 32] {
                break;
            }
        }

        let epoch_start_block_height = height / 2016 * 2016;

        let (epoch_start_timestamp, expected_bits) = if network == Network::Regtest {
            (0, block_header.bits.to_consensus())
        } else {
            let epoch_start_block_hash = rpc
                .client
                .get_block_hash(epoch_start_block_height)
                .await
                .wrap_err(format!(
                    "Failed to get block hash at height {}",
                    epoch_start_block_height
                ))?;
            let epoch_start_block_header = rpc
                .client
                .get_block_header(&epoch_start_block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block header with block hash {}",
                    epoch_start_block_hash
                ))?;
            let bits = if network == Network::Testnet4 {
                // Real difficulty will show up at epoch start block no matter what
                epoch_start_block_header.bits.to_consensus()
            } else {
                block_header.bits.to_consensus()
            };

            (epoch_start_block_header.time, bits)
        };

        let block_info = rpc
            .client
            .get_block_info(&block_hash)
            .await
            .wrap_err(format!(
                "Failed to get block info with block hash {}",
                block_hash
            ))?;

        let total_work = block_info.chainwork;

        let total_work: [u8; 32] = total_work.try_into().expect("Total work is 32 bytes");

        let mut block_hashes_mmr = MMRGuest::new();
        block_hashes_mmr.append(block_hash.to_byte_array());

        let chain_state = ChainState {
            block_height: height as u32,
            total_work,
            best_block_hash: block_hash.to_byte_array(),
            current_target_bits: expected_bits,
            epoch_start_time: epoch_start_timestamp,
            prev_11_timestamps: last_11_block_timestamps,
            block_hashes_mmr,
        };
        Ok(chain_state)
    }

    /// Proves the work only proof for the given HCP receipt.
    pub fn prove_work_only(
        &self,
        hcp_receipt: Receipt,
    ) -> Result<(Receipt, WorkOnlyCircuitOutput), HeaderChainProverError> {
        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::from_slice(&hcp_receipt.journal.bytes)
                .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;
        let input = WorkOnlyCircuitInput {
            header_chain_circuit_output: block_header_circuit_output,
        };
        let mut env = ExecutorEnv::builder();

        env.write_slice(&borsh::to_vec(&input).wrap_err(BridgeError::BorshError)?);

        env.add_assumption(hcp_receipt);

        let env = env
            .build()
            .map_err(|e| eyre::eyre!(e))
            .wrap_err("Failed to build environment")?;

        let prover = risc0_zkvm::default_prover();

        let elf = match self.network {
            Network::Bitcoin => MAINNET_WORK_ONLY_ELF,
            Network::Testnet4 => TESTNET4_WORK_ONLY_ELF,
            Network::Signet => SIGNET_WORK_ONLY_ELF,
            Network::Regtest => REGTEST_WORK_ONLY_ELF,
            _ => Err(BridgeError::UnsupportedNetwork.into_eyre())?,
        };

        tracing::warn!("Starting proving HCP work only proof for creating a watchtower challenge");
        let receipt = if !is_dev_mode() {
            prover
                .prove_with_opts(env, elf, &ProverOpts::groth16())
                .map_err(|e| eyre::eyre!(e))?
                .receipt
        } else {
            let stark_receipt = prover
                .prove_with_opts(env, elf, &ProverOpts::succinct())
                .map_err(|e| eyre::eyre!(e))?
                .receipt;
            let journal = stark_receipt.journal.bytes.clone();
            dev_stark_to_risc0_g16(stark_receipt, &journal)?
        };
        tracing::warn!("HCP work only proof proof generated for creating a watchtower challenge");
        let work_output: WorkOnlyCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
            .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;

        Ok((receipt, work_output))
    }

    /// Proves blocks till the block with hash `current_block_hash`.
    ///
    /// # Parameters
    ///
    /// - `current_block_hash`: Hash of the target block
    /// - `block_headers`: Previous block headers before the target block
    /// - `previous_proof`: Previous proof's receipt
    #[tracing::instrument(skip_all)]
    async fn prove_and_save_block(
        &self,
        current_block_hash: BlockHash,
        block_headers: Vec<Header>,
        previous_proof: Receipt,
    ) -> Result<Receipt, BridgeError> {
        tracing::debug!(
            "Prover starts proving {} blocks ending with block with hash {}",
            block_headers.len(),
            current_block_hash
        );

        let headers: Vec<CircuitBlockHeader> = block_headers.into_iter().map(Into::into).collect();
        let receipt = self.prove_block_headers(previous_proof, headers)?;

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
        prev_receipt: Receipt,
        block_headers: Vec<CircuitBlockHeader>,
    ) -> Result<Receipt, HeaderChainProverError> {
        // Prepare proof input.
        let prev_output: BlockHeaderCircuitOutput = borsh::from_slice(&prev_receipt.journal.bytes)
            .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;
        let method_id = prev_output.method_id;

        let prev_proof = HeaderChainPrevProofType::PrevProof(prev_output);

        let input = HeaderChainCircuitInput {
            method_id,
            prev_proof,
            block_headers,
        };
        Self::prove_with_input(input, Some(prev_receipt), self.network)
    }

    pub fn prove_genesis_block(
        genesis_chain_state: ChainState,
        network: Network,
    ) -> Result<Receipt, HeaderChainProverError> {
        let image_id = match network {
            Network::Bitcoin => *MAINNET_IMAGE_ID,
            Network::Testnet => *TESTNET4_IMAGE_ID,
            Network::Testnet4 => *TESTNET4_IMAGE_ID,
            Network::Signet => *SIGNET_IMAGE_ID,
            Network::Regtest => *REGTEST_IMAGE_ID,
            _ => Err(BridgeError::UnsupportedNetwork.into_eyre())?,
        };
        let header_chain_circuit_type = HeaderChainPrevProofType::GenesisBlock(genesis_chain_state);
        let input = HeaderChainCircuitInput {
            method_id: image_id,
            prev_proof: header_chain_circuit_type,
            block_headers: vec![],
        };

        Self::prove_with_input(input, None, network)
    }

    fn prove_with_input(
        input: HeaderChainCircuitInput,
        prev_receipt: Option<Receipt>,
        network: Network,
    ) -> Result<Receipt, HeaderChainProverError> {
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

        let elf = match network {
            Network::Bitcoin => MAINNET_HEADER_CHAIN_ELF,
            Network::Testnet => TESTNET4_HEADER_CHAIN_ELF,
            Network::Testnet4 => TESTNET4_HEADER_CHAIN_ELF,
            Network::Signet => SIGNET_HEADER_CHAIN_ELF,
            Network::Regtest => REGTEST_HEADER_CHAIN_ELF,
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

    /// Produces a proof for the chain up to the block with the given hash.
    ///
    /// # Returns
    ///
    /// - [`Receipt`]: Specified block's proof receipt
    /// - [`u64`]: Height of the proven header chain
    pub async fn prove_till_hash(
        &self,
        block_hash: BlockHash,
    ) -> Result<(Receipt, u64), BridgeError> {
        let (_, _, height) = self
            .db
            .get_block_info_from_hash_hcp(None, block_hash)
            .await?
            .ok_or(eyre::eyre!("Block not found in prove_till_hash"))?;

        let latest_proven_block = self
            .db
            .get_latest_proven_block_info_until_height(None, height)
            .await?
            .ok_or_eyre("No proofs found before the given block hash")?;

        if latest_proven_block.2 == height as u64 {
            let receipt = self
                .db
                .get_block_proof_by_hash(None, latest_proven_block.0)
                .await
                .wrap_err("Failed to get block proof")?
                .ok_or(eyre!("Failed to get block proof"))?;
            return Ok((receipt, height as u64));
        }

        let block_headers = self
            .db
            .get_block_info_from_range(None, latest_proven_block.2 + 1, height.into())
            .await?
            .into_iter()
            .map(|(_hash, header)| header)
            .collect::<Vec<_>>();

        let previous_proof = self
            .db
            .get_block_proof_by_hash(None, latest_proven_block.0)
            .await?
            .ok_or(eyre::eyre!("No proven block found"))?;
        let receipt = self
            .prove_and_save_block(block_hash, block_headers, previous_proof)
            .await?;
        tracing::info!("Generated new proof for height {}", height);
        Ok((receipt, height as u64))
    }

    /// Gets the proof of the latest finalized blockchain tip. If the finalized
    /// blockchain tip isn't yet proven, it will be proven first in batches
    /// (last proven block in database to finalized blockchain tip).
    ///
    /// # Returns
    ///
    /// - [`Receipt`]: Specified block's proof receipt
    /// - [`u64`]: Height of the proven header chain
    pub async fn get_tip_header_chain_proof(&self) -> Result<(Receipt, u64), BridgeError> {
        let max_height = self.db.get_latest_finalized_block_height(None).await?;

        if let Some(max_height) = max_height {
            let block_hash = self
                .db
                .get_block_info_from_range(None, max_height, max_height)
                .await?
                .into_iter()
                .next()
                .expect("Block should be in table")
                .0;
            Ok(self.prove_till_hash(block_hash).await?)
        } else {
            Err(eyre::eyre!("No finalized blocks in header chain proofs table").into())
        }
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
            .save_unproven_finalized_block(
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
        let non_proven_block = if let Some(block) = self.db.get_next_unproven_block(None).await? {
            block
        } else {
            return Ok(false);
        };
        let tip_height = self
            .db
            .get_latest_finalized_block_height(None)
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

    /// Proves blocks if the batch is ready. If not, skips.
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
            .prove_and_save_block(current_block_hash, block_headers, prev_proof)
            .await?;
        tracing::info!(
            "Header chain proof generated for block with hash {:?} and height {}",
            current_block_hash,
            current_block_height,
        );

        Ok(Some(receipt))
    }
}

#[cfg(test)]
mod tests {
    use crate::extended_rpc::ExtendedRpc;
    use crate::header_chain_prover::HeaderChainProver;
    use crate::test::common::*;
    use crate::verifier::VerifierServer;
    use crate::{database::Database, test::common::citrea::MockCitreaClient};
    use bitcoin::{block::Header, hashes::Hash, BlockHash, Network};
    use bitcoincore_rpc::RpcApi;
    use circuits_lib::header_chain::{
        mmr_guest::MMRGuest, BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader,
    };
    use secp256k1::rand::{self, Rng};

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

            let _ignore_errors = db
                .save_unproven_finalized_block(None, hash, header, i)
                .await;
        }

        headers
    }

    #[ignore = "This test is requires env var at build time, but it works, try it out"]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_generate_chain_state_from_height() {
        // set BITCOIN_NETWORK to regtest
        std::env::set_var("BITCOIN_NETWORK", "regtest");
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        // randomly select a number of blocks from 12 to 2116
        let num_blocks: u64 = rand::rng().random_range(12..2116);

        // Save some initial blocks.
        let headers = mine_and_get_first_n_block_headers(rpc.clone(), db.clone(), num_blocks).await;

        let chain_state = HeaderChainProver::get_chain_state_from_height(
            rpc.clone(),
            num_blocks,
            Network::Regtest,
        )
        .await
        .unwrap();

        let mut expected_chain_state = ChainState::genesis_state();
        expected_chain_state.apply_block_headers(
            headers
                .iter()
                .map(|header| CircuitBlockHeader::from(*header))
                .collect::<Vec<_>>(),
        );

        expected_chain_state.block_hashes_mmr = MMRGuest::new();

        println!("Chain state: {:#?}", chain_state);
        println!("Expected chain state: {:#?}", expected_chain_state);

        assert_eq!(chain_state, expected_chain_state);
    }

    #[ignore = "This test is requires env var at build time & testnet4, but it works, try it out"]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_generate_chain_state_from_height_testnet4() {
        // set BITCOIN_NETWORK to regtest
        std::env::set_var("BITCOIN_NETWORK", "testnet4");
        let rpc = ExtendedRpc::connect(
            "http://127.0.0.1:48332".to_string(),
            "admin".to_string().into(),
            "admin".to_string().into(),
        )
        .await
        .unwrap();

        // randomly select a number of blocks from 12 to 2116
        let num_blocks: u64 = rand::rng().random_range(12..2116);

        // Save some initial blocks.
        let mut headers = Vec::new();
        for i in 0..=num_blocks {
            let hash = rpc.client.get_block_hash(i).await.unwrap();
            let header = rpc.client.get_block_header(&hash).await.unwrap();
            headers.push(header);
        }

        let chain_state = HeaderChainProver::get_chain_state_from_height(
            rpc.clone(),
            num_blocks,
            Network::Testnet4,
        )
        .await
        .unwrap();

        let mut expected_chain_state = ChainState::genesis_state();
        expected_chain_state.apply_block_headers(
            headers
                .iter()
                .map(|header| CircuitBlockHeader::from(*header))
                .collect::<Vec<_>>(),
        );

        expected_chain_state.block_hashes_mmr = MMRGuest::new();

        println!("Chain state: {:#?}", chain_state);
        println!("Expected chain state: {:#?}", expected_chain_state);

        assert_eq!(chain_state, expected_chain_state);
    }

    #[tokio::test]
    async fn test_fetch_and_save_missing_blocks() {
        // test these functions:
        // save_block_infos_within_range
        // fetch_and_save_missing_blocks
        // get_block_info_from_hash_hcp
        // get_latest_proven_block_info_until_height
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        let current_height = rpc.client.get_block_count().await.unwrap();
        let current_hcp_height = prover
            .db
            .get_latest_finalized_block_height(None)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(current_height, current_hcp_height);

        prover
            .db
            .fetch_and_save_missing_blocks(
                &rpc,
                config.protocol_paramset().genesis_height,
                current_height as u32 + 1,
            )
            .await
            .unwrap();

        let current_hcp_height = prover
            .db
            .get_latest_finalized_block_height(None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current_height, current_hcp_height);

        let test_height = current_height as u32 / 2;

        let block_hash = rpc.client.get_block_hash(test_height as u64).await.unwrap();
        let block_info = prover
            .db
            .get_block_info_from_hash_hcp(None, block_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(block_info.2, test_height);

        let receipt_1 = prover.prove_till_hash(block_hash).await.unwrap();
        let latest_proven_block = prover
            .db
            .get_latest_proven_block_info_until_height(None, current_hcp_height as u32)
            .await
            .unwrap()
            .unwrap();

        let receipt_2 = prover.prove_till_hash(block_hash).await.unwrap();

        assert_eq!(receipt_1.0.journal, receipt_2.0.journal);

        assert_eq!(latest_proven_block.2, test_height as u64);
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
        let (receipt, _) = prover.prove_till_hash(hash).await.unwrap();
        let db_receipt = prover
            .db
            .get_block_proof_by_hash(None, hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.journal, db_receipt.journal);
        assert_eq!(receipt.metadata, db_receipt.metadata);
    }

    #[tokio::test]
    async fn prove_a_block_from_database() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        // Set up the next non proven block.
        let height = 1;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let genesis_hash = rpc.client.get_block_hash(0).await.unwrap();
        let (genesis_receipt, _) = prover.prove_till_hash(genesis_hash).await.unwrap();
        let block = rpc.client.get_block(&hash).await.unwrap();
        let header = block.header;
        prover
            .db
            .save_unproven_finalized_block(None, hash, header, height)
            .await
            .unwrap();

        let receipt = prover
            .prove_and_save_block(hash, vec![header], genesis_receipt)
            .await
            .unwrap();

        let (read_recipt, _) = prover.prove_till_hash(hash).await.unwrap();
        assert_eq!(receipt.journal, read_recipt.journal);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prove_block_headers_genesis() {
        let genesis_state = ChainState::genesis_state();

        let receipt =
            HeaderChainProver::prove_genesis_block(genesis_state, Network::Regtest).unwrap();

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
        let genesis_state = ChainState::genesis_state();

        let receipt =
            HeaderChainProver::prove_genesis_block(genesis_state, Network::Regtest).unwrap();

        let block_headers = mine_and_get_first_n_block_headers(rpc, prover.db.clone(), 3)
            .await
            .iter()
            .map(|header| CircuitBlockHeader::from(*header))
            .collect::<Vec<_>>();
        let receipt = prover
            .prove_block_headers(receipt, block_headers[0..2].to_vec())
            .unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();

        println!("Proof journal output: {:?}", output);

        assert_eq!(output.chain_state.block_height, 1);
    }

    #[tokio::test]
    async fn prove_till_hash_intermediate_blocks() {
        // this test does assume config start height is bigger than 3
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        for i in (0..3).rev() {
            let hash = rpc.client.get_block_hash(i).await.unwrap();
            let (proof, _) = prover.prove_till_hash(hash).await.unwrap();
            let db_proof = db
                .get_block_proof_by_hash(None, hash)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.journal, db_proof.journal);
        }
        let hash = rpc.client.get_block_hash(5).await.unwrap();
        let (proof, _) = prover.prove_till_hash(hash).await.unwrap();
        let db_proof = db
            .get_block_proof_by_hash(None, hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(proof.journal, db_proof.journal);
    }

    #[tokio::test]
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
        let (genesis_block_proof, _) = prover.prove_till_hash(genesis_hash).await.unwrap();
        let db_proof = db
            .get_block_proof_by_hash(None, genesis_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(genesis_block_proof.journal, db_proof.journal);

        assert!(
            prover.is_batch_ready().await.unwrap()
                == (config.protocol_paramset().start_height > batch_size)
        );

        // Mining required amount of blocks should make batch proving ready.
        let _headers =
            mine_and_get_first_n_block_headers(rpc.clone(), db, batch_size as u64 + 1).await;
        assert!(prover.is_batch_ready().await.unwrap());
    }

    #[tokio::test]
    async fn prove_if_ready() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save some initial blocks.
        mine_and_get_first_n_block_headers(rpc.clone(), db.clone(), 2).await;

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        let latest_proven_block_height = db.get_next_unproven_block(None).await.unwrap().unwrap().2;
        let _block_headers = mine_and_get_first_n_block_headers(
            rpc.clone(),
            db.clone(),
            latest_proven_block_height + batch_size as u64,
        )
        .await;

        let receipt = prover.prove_if_ready().await.unwrap().unwrap();
        let latest_proof = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        let get_receipt = prover
            .db
            .get_block_proof_by_hash(None, latest_proof.0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.journal, get_receipt.journal);
        assert_eq!(receipt.metadata, get_receipt.metadata);
    }

    #[tokio::test]
    async fn prove_and_get_non_targeted_block() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        // Save some initial blocks.
        mine_and_get_first_n_block_headers(rpc.clone(), db.clone(), 2).await;

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        let latest_proven_block_height = db.get_next_unproven_block(None).await.unwrap().unwrap().2;
        let _block_headers = mine_and_get_first_n_block_headers(
            rpc.clone(),
            db.clone(),
            latest_proven_block_height + batch_size as u64,
        )
        .await;

        let receipt = prover.prove_if_ready().await.unwrap().unwrap();
        let latest_proof = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        let get_receipt = prover
            .db
            .get_block_proof_by_hash(None, latest_proof.0)
            .await
            .unwrap()
            .unwrap();
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
        let _receipt = prover.get_tip_header_chain_proof().await.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "automation")]
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

            db.save_unproven_finalized_block(None, block.block_hash(), block.header, i)
                .await
                .unwrap();
        }

        let verifier = VerifierServer::<MockCitreaClient>::new(config)
            .await
            .unwrap();
        verifier.start_background_tasks().await.unwrap();
        // Make sure enough blocks to prove and is finalized.
        rpc.mine_blocks((batch_size + 10).into()).await.unwrap();

        // Aim for a proved block that is added to the database by the verifier.
        let height = batch_size;
        let hash = rpc.client.get_block_hash(height.into()).await.unwrap();

        poll_until_condition(
            async || {
                Ok(verifier
                    .verifier
                    .header_chain_prover
                    .db
                    .get_block_proof_by_hash(None, hash)
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
