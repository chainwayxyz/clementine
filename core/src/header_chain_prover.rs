//! # Header Chain Prover
//!
//! This module contains utilities for proving Bitcoin block headers. This
//! module must be fed with new blocks via the database. Proofs are made only
//! when a block's proof is requested.

use crate::builder::block_cache::BlockCache;
use crate::config::protocol::ProtocolParamset;
use crate::database::DatabaseTransaction;
use crate::errors::ResultExt;
use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
};
use bitcoin::block::Header;
use bitcoin::params::Params;
use bitcoin::{hashes::Hash, BlockHash, CompactTarget, Network};
use bitcoincore_rpc::RpcApi;
use bridge_circuit_host::guests::{Guest, NetworkGuests};
use bridge_circuit_host::sp1::{ensure_assumption, prove, verify, Backend, GuestInput};
use circuits_lib::bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput};
use circuits_lib::common::sp1::Receipt;
use circuits_lib::header_chain::mmr_guest::MMRGuest;
use circuits_lib::header_chain::{
    BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader, HeaderChainCircuitInput,
    HeaderChainPrevProofType,
};
use eyre::{eyre, Context};
use std::{
    fs::File,
    io::{BufReader, Read},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HeaderChainProverError {
    #[error("Error while de/serializing object")]
    ProverDeSerializationError,
    #[error("Header chain prover not initialized due to config")]
    HeaderChainProverNotInitialized,
    #[error("Unsupported network")]
    UnsupportedNetwork,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, Clone)]
pub struct HeaderChainProver {
    db: Database,
    rpc: ExtendedBitcoinRpc,
    paramset: &'static ProtocolParamset,
    guests: &'static NetworkGuests,
    backend: Backend,
}

impl HeaderChainProver {
    /// Creates a new [`HeaderChainProver`] instance. Also saves a proof
    /// assumption if specified in the config.
    pub async fn new(
        config: &BridgeConfig,
        rpc: ExtendedBitcoinRpc,
    ) -> Result<Self, HeaderChainProverError> {
        let backend = Backend::from_env()?;
        let paramset = config.protocol_paramset();
        let guests = NetworkGuests::for_network(paramset.network)
            .ok_or(HeaderChainProverError::UnsupportedNetwork)?;
        let db = Database::new(config).await.map_to_eyre()?;
        let tip_height = rpc.get_current_chain_height().await.map_to_eyre()?;
        let first_height = paramset.start_height.max(paramset.genesis_height);
        if !paramset.is_block_finalized(first_height, tip_height) {
            return Err(eyre::eyre!(
                "Start or genesis height is not finalized: {} < {}",
                tip_height,
                first_height + paramset.finality_depth - 1
            )
            .into());
        }
        db.fetch_and_save_missing_blocks(
            None,
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

            let network = config.protocol_paramset().network;
            let header_chain_key = guests.header_chain.key;

            if proof_output.method_id != header_chain_key.recursion {
                return Err(eyre::eyre!(
                    "Header chain proof assumption file Method ID mismatch for our current network ({:?}): got {:?}, expected {:?}",
                    network,
                    proof_output.method_id,
                    header_chain_key.recursion
                )
                .into());
            }

            if let Err(e) = ensure_assumption(&proof) {
                return Err(
                    eyre::eyre!("Header chain proof assumption file is not usable: {e}").into(),
                );
            }

            if let Err(e) = verify(&proof, header_chain_key, backend == Backend::Mock).await {
                return Err(eyre::eyre!(
                    "Header chain proof assumption file verification failed for our current network ({:?}): {e}",
                    network
                )
                .into());
            }

            let expected_genesis = config.protocol_paramset().genesis_chain_state_hash;
            if proof_output.genesis_state_hash != expected_genesis {
                return Err(eyre::eyre!(
                    "Header chain proof assumption file genesis state hash mismatch: got {}, expected {}",
                    hex::encode(proof_output.genesis_state_hash),
                    hex::encode(expected_genesis)
                )
                .into());
            }

            // Create block entry, if not exists.
            let chain_state = &proof_output.chain_state;
            let block_hash = BlockHash::from_raw_hash(
                Hash::from_slice(&chain_state.best_block_hash).map_to_eyre()?,
            );
            let block_header = rpc.get_block_header(&block_hash).await.wrap_err(format!(
                "Failed to get block header with block hash {block_hash} (retrieved from assumption file)",
            ))?;
            let block_info = rpc.get_block_info(&block_hash).await.wrap_err(format!(
                "Failed to get block info with block hash {block_hash} (retrieved from assumption file)"
            ))?;

            // Bitcoin Core reports -1 confirmations for blocks outside the active chain.
            if block_info.confirmations < 1 {
                return Err(eyre::eyre!(
                    "Header chain proof assumption file block {block_hash} is not in the active chain"
                )
                .into());
            }
            if block_info.height != chain_state.block_height as usize {
                return Err(eyre::eyre!(
                    "Header chain proof assumption file height mismatch for block {block_hash}: proof has {}, RPC has {}",
                    chain_state.block_height,
                    block_info.height
                )
                .into());
            }
            if block_info.chainwork != chain_state.total_work {
                return Err(eyre::eyre!(
                    "Header chain proof assumption file total work mismatch for block {block_hash}: proof has {}, RPC has {}",
                    hex::encode(chain_state.total_work),
                    hex::encode(&block_info.chainwork)
                )
                .into());
            }

            tracing::info!(
                "Adding proof assumption for a block with hash of {:?}, header of {:?} and height of {}",
                block_hash,
                block_header,
                block_info.height
            );

            // An existing row for this block is kept.
            db.save_unproven_finalized_block(
                None,
                block_hash,
                block_header,
                chain_state.block_height.into(),
            )
            .await
            .map_to_eyre()?;

            db.set_block_proof(None, block_hash, proof)
                .await
                .map_to_eyre()?;
        } else {
            let genesis_block_hash = rpc
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

            let genesis_block_header =
                rpc.get_block_header(&genesis_block_hash)
                    .await
                    .wrap_err(format!(
                        "Failed to get genesis block header at height {}",
                        config.protocol_paramset().genesis_height
                    ))?;

            let _ = db
                .save_unproven_finalized_block(
                    None,
                    genesis_block_hash,
                    genesis_block_header,
                    config.protocol_paramset().genesis_height.into(),
                )
                .await;
        }

        Ok(HeaderChainProver {
            db,
            rpc,
            paramset,
            guests,
            backend,
        })
    }

    /// SP1 proving backend, read from `SP1_PROVER` when the prover is created.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub async fn get_chain_state_from_height(
        rpc: &ExtendedBitcoinRpc,
        height: u64,
        network: Network,
    ) -> Result<ChainState, HeaderChainProverError> {
        let block_hash = rpc
            .get_block_hash(height)
            .await
            .wrap_err(format!("Failed to get block hash at height {height}"))?;

        let block_header = rpc.get_block_header(&block_hash).await.wrap_err(format!(
            "Failed to get block header with block hash {block_hash}"
        ))?;

        let mut last_11_block_timestamps: [u32; 11] = [0; 11];
        let mut last_block_hash = block_hash;
        let mut last_block_height = height;
        for _ in 0..11 {
            let block_header = rpc
                .get_block_header(&last_block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block header with block hash {last_block_hash}"
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
                .get_block_hash(epoch_start_block_height)
                .await
                .wrap_err(format!(
                    "Failed to get block hash at height {epoch_start_block_height}"
                ))?;
            let epoch_start_block_header = rpc
                .get_block_header(&epoch_start_block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block header with block hash {epoch_start_block_hash}"
                ))?;
            let bits = if network == Network::Testnet4 {
                // Real difficulty will show up at epoch start block no matter what
                epoch_start_block_header.bits.to_consensus()
            } else {
                block_header.bits.to_consensus()
            };

            (epoch_start_block_header.time, bits)
        };

        // After the last block of an epoch, the guest already holds the next epoch's target.
        let expected_bits = if network != Network::Regtest && height % 2016 == 2015 {
            next_epoch_bits(
                network,
                epoch_start_timestamp,
                block_header.time,
                expected_bits,
            )
        } else {
            expected_bits
        };

        let block_info = rpc.get_block_info(&block_hash).await.wrap_err(format!(
            "Failed to get block info with block hash {block_hash}"
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
    pub async fn prove_work_only(
        &self,
        hcp_receipt: Receipt,
    ) -> Result<(Receipt, WorkOnlyCircuitOutput), HeaderChainProverError> {
        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::from_slice(&hcp_receipt.journal.bytes)
                .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;
        let input = WorkOnlyCircuitInput {
            header_chain_circuit_output: block_header_circuit_output,
        };
        tracing::warn!("Starting proving HCP work only proof for creating a watchtower challenge");
        let proof = prove(
            &self.guests.work_only,
            GuestInput::new(&input)?.with_assumption(&hcp_receipt)?,
            self.backend,
        );

        #[cfg(test)]
        let proof = crate::test::common::shared_proofs::share(
            &self.guests.work_only,
            self.backend,
            &input,
            proof,
        );

        let receipt = proof.await.wrap_err("Failed to prove work only")?;
        tracing::warn!("HCP work only proof generated for creating a watchtower challenge");
        let work_output: WorkOnlyCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
            .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;

        // Receipt verification only binds the receipt to the work only circuit, so a valid
        // receipt for another header chain proof would pass it.
        if work_output != work_only_output(&input.header_chain_circuit_output) {
            return Err(eyre!(
                "Work only receipt does not prove the work of the given header chain proof"
            )
            .into());
        }

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
        let receipt = Self::prove_block_headers(
            &self.guests.header_chain,
            self.backend,
            previous_proof,
            headers,
        )
        .await
        .wrap_err("Failed to prove block headers")?;

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
    async fn prove_block_headers(
        header_chain: &Guest,
        backend: Backend,
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
        Self::prove_with_input(input, Some(prev_receipt), header_chain, backend).await
    }

    /// Proves `block_headers` on top of `genesis_chain_state`, without a
    /// previous proof.
    async fn prove_from_genesis(
        genesis_chain_state: ChainState,
        block_headers: Vec<CircuitBlockHeader>,
        header_chain: &Guest,
        backend: Backend,
    ) -> Result<Receipt, HeaderChainProverError> {
        let header_chain_circuit_type = HeaderChainPrevProofType::GenesisBlock(genesis_chain_state);
        let input = HeaderChainCircuitInput {
            method_id: header_chain.key.recursion,
            prev_proof: header_chain_circuit_type,
            block_headers,
        };

        Self::prove_with_input(input, None, header_chain, backend).await
    }

    /// Proves the chain from the genesis chain state till the block with hash
    /// `block_hash` at `height`, and saves the proof.
    async fn prove_and_save_from_genesis(
        &self,
        block_hash: BlockHash,
        height: u32,
    ) -> Result<Receipt, BridgeError> {
        let genesis_height = self.paramset.genesis_height;
        if height < genesis_height {
            return Err(eyre!(
                "Block {block_hash} at height {height} is below genesis height {genesis_height}"
            )
            .into());
        }

        let genesis_chain_state = Self::get_chain_state_from_height(
            &self.rpc,
            genesis_height.into(),
            self.paramset.network,
        )
        .await?;
        if genesis_chain_state.to_hash() != self.paramset.genesis_chain_state_hash {
            return Err(eyre!(
                "Genesis chain state hash mismatch: got {}, expected {}",
                hex::encode(genesis_chain_state.to_hash()),
                hex::encode(self.paramset.genesis_chain_state_hash)
            )
            .into());
        }

        let block_headers = self
            .db
            .get_block_info_from_range(None, u64::from(genesis_height) + 1, height.into())
            .await?
            .into_iter()
            .map(|(_hash, header)| header.into())
            .collect::<Vec<CircuitBlockHeader>>();
        tracing::debug!(
            "Prover starts proving {} blocks from genesis, ending with block with hash {}",
            block_headers.len(),
            block_hash
        );

        let receipt = Self::prove_from_genesis(
            genesis_chain_state,
            block_headers,
            &self.guests.header_chain,
            self.backend,
        )
        .await
        .wrap_err("Failed to prove block headers from genesis")?;

        self.db
            .set_block_proof(None, block_hash, receipt.clone())
            .await?;

        Ok(receipt)
    }

    async fn prove_with_input(
        input: HeaderChainCircuitInput,
        prev_receipt: Option<Receipt>,
        header_chain: &Guest,
        backend: Backend,
    ) -> Result<Receipt, HeaderChainProverError> {
        let mut guest_input = GuestInput::new(&input)?;
        if let Some(prev_receipt) = &prev_receipt {
            guest_input = guest_input.with_assumption(prev_receipt)?;
        }

        let proof = prove(header_chain, guest_input, backend);

        #[cfg(test)]
        let proof = crate::test::common::shared_proofs::share(header_chain, backend, &input, proof);

        let receipt = proof.await?;
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
            .wrap_err(HeaderChainProverError::ProverDeSerializationError)?;
        Self::check_output_matches_input(&input, &output)?;
        tracing::debug!(
            "Proof receipt for header chain circuit input {:?}: {:?}",
            input,
            receipt
        );

        Ok(receipt)
    }

    /// Checks that a header chain output extends `input` to the requested tip.
    ///
    /// Receipt verification only binds the receipt to the circuit, so a valid receipt for other
    /// input, such as another genesis state or an older tip, would pass it. The genesis state
    /// hash, tip hash and tip height fix the rest of the output.
    fn check_output_matches_input(
        input: &HeaderChainCircuitInput,
        output: &BlockHeaderCircuitOutput,
    ) -> Result<(), HeaderChainProverError> {
        let (genesis_state_hash, start) = match &input.prev_proof {
            HeaderChainPrevProofType::GenesisBlock(state) => (state.to_hash(), state),
            HeaderChainPrevProofType::PrevProof(prev) => {
                (prev.genesis_state_hash, &prev.chain_state)
            }
        };
        let tip_hash = input.block_headers.last().map_or(
            start.best_block_hash,
            CircuitBlockHeader::compute_block_hash,
        );
        let header_count =
            u32::try_from(input.block_headers.len()).wrap_err("Too many block headers to prove")?;
        // Wraps like the guest: the regtest genesis state, before any header, is at u32::MAX.
        let tip_height = start.block_height.wrapping_add(header_count);

        if output.method_id != input.method_id
            || output.genesis_state_hash != genesis_state_hash
            || output.chain_state.best_block_hash != tip_hash
            || output.chain_state.block_height != tip_height
        {
            return Err(eyre!(
                "Header chain receipt proves height {} from genesis state {}, instead of the requested height {tip_height} from genesis state {}",
                output.chain_state.block_height,
                hex::encode(output.genesis_state_hash),
                hex::encode(genesis_state_hash)
            )
            .into());
        }
        Ok(())
    }

    /// Produces a proof for the chain up to the block with the given hash. If
    /// no block at or below it is proven, the proof starts from the genesis
    /// chain state.
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

        let Some(latest_proven_block) = self
            .db
            .get_latest_proven_block_info_until_height(None, height)
            .await?
        else {
            let receipt = self.prove_and_save_from_genesis(block_hash, height).await?;
            tracing::info!("Generated new proof from genesis for height {}", height);
            return Ok((receipt, height as u64));
        };

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
    /// blockchain tip isn't yet proven, it will be proven first (last proven
    /// block in database, or genesis, to finalized blockchain tip).
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
        let block_hash = block_cache.block.block_hash();

        let block_header = block_cache.block.header;

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
}

/// The output that the work only circuit commits for `hcp`: the low 128 bits of its big-endian
/// total work, and its genesis state hash.
fn work_only_output(hcp: &BlockHeaderCircuitOutput) -> WorkOnlyCircuitOutput {
    WorkOnlyCircuitOutput {
        work_u128: hcp.chain_state.total_work[16..]
            .try_into()
            .expect("total work is 32 bytes"),
        genesis_state_hash: hcp.genesis_state_hash,
    }
}

/// Target bits of the next epoch, computed from the epoch's start time, the time of its last
/// block and its target bits, with the retarget rules of the header chain guest.
fn next_epoch_bits(
    network: Network,
    epoch_start_time: u32,
    last_block_time: u32,
    bits: u32,
) -> u32 {
    let mut params = Params::new(network);
    if network == Network::Signet {
        // Citrea's signet has 10-second blocks (`EXPECTED_EPOCH_TIMESPAN` in the guest).
        params.pow_target_timespan = 60 * 24 * 14;
    }
    CompactTarget::from_next_work_required(
        CompactTarget::from_consensus(bits),
        last_block_time.saturating_sub(epoch_start_time).into(),
        &params,
    )
    .to_consensus()
}

#[cfg(test)]
mod tests {
    use crate::database::Database;
    use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
    use crate::header_chain_prover::HeaderChainProver;
    use crate::test::common::*;
    use bitcoin::{block::Header, hashes::Hash, BlockHash, Network};
    use bitcoincore_rpc::RpcApi;
    use bridge_circuit_host::guests::Guest;
    use bridge_circuit_host::sp1::{prove, Backend, GuestInput, ProofKind};
    use circuits_lib::bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput};
    use circuits_lib::header_chain::{
        mmr_guest::MMRGuest, BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader,
        HeaderChainCircuitInput, HeaderChainPrevProofType,
    };
    use secp256k1::rand::{self, Rng};

    /// Mines `block_num` amount of blocks (if not already mined) and returns
    /// the first `block_num` block headers in blockchain.
    async fn mine_and_get_first_n_block_headers(
        rpc: ExtendedBitcoinRpc,
        db: Database,
        block_num: u64,
    ) -> Vec<Header> {
        let height = rpc.get_block_count().await.unwrap();
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
            let hash = rpc.get_block_hash(i).await.unwrap();
            let header = rpc.get_block_header(&hash).await.unwrap();

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

        let chain_state =
            HeaderChainProver::get_chain_state_from_height(&rpc, num_blocks, Network::Regtest)
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

        println!("Chain state: {chain_state:#?}");
        println!("Expected chain state: {expected_chain_state:#?}");

        assert_eq!(chain_state, expected_chain_state);
    }

    #[ignore = "This test requires env var at build time & testnet4, but it works, try it out"]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_generate_chain_state_from_height_testnet4() {
        // set BITCOIN_NETWORK to testnet4
        std::env::set_var("BITCOIN_NETWORK", "testnet4");
        let rpc = ExtendedBitcoinRpc::connect(
            "http://127.0.0.1:48332".to_string(),
            "admin".to_string().into(),
            "admin".to_string().into(),
            None,
        )
        .await
        .unwrap();

        // randomly select a number of blocks from 12 to 2116
        let num_blocks: u64 = rand::rng().random_range(12..2116);

        // Save some initial blocks.
        let mut headers = Vec::new();
        for i in 0..=num_blocks {
            let hash = rpc.get_block_hash(i).await.unwrap();
            let header = rpc.get_block_header(&hash).await.unwrap();
            headers.push(header);
        }

        let chain_state =
            HeaderChainProver::get_chain_state_from_height(&rpc, num_blocks, Network::Testnet4)
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

        println!("Chain state: {chain_state:#?}");
        println!("Expected chain state: {expected_chain_state:#?}");

        assert_eq!(chain_state, expected_chain_state);
    }

    #[test]
    fn next_epoch_bits_matches_guest_retargets() {
        // Mainnet epochs from `DIFFICULTY_ADJUSTMENTS` in the header chain circuit tests:
        // capped at the maximum target, a normal retarget, clamped, and a recent retarget.
        for (start_time, end_time, bits, next_bits) in [
            (1231006505, 1233061996, 486604799, 486604799),
            (1261130161, 1262152739, 486604799, 486594666),
            (1279008237, 1279297671, 470131700, 469854461),
            (1728456399, 1729620194, 386076365, 386068776),
        ] {
            assert_eq!(
                super::next_epoch_bits(Network::Bitcoin, start_time, end_time, bits),
                next_bits
            );
        }
        // An epoch of exactly 14 days keeps the target on Citrea's signet.
        assert_eq!(
            super::next_epoch_bits(Network::Signet, 0, 60 * 24 * 14, 0x1d00ffff),
            0x1d00ffff
        );
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

        let current_height = rpc.get_block_count().await.unwrap();
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
                None,
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

        let block_hash = rpc.get_block_hash(test_height as u64).await.unwrap();
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
        let hash = rpc.get_block_hash(0).await.unwrap();
        let (receipt, _) = prover.prove_till_hash(hash).await.unwrap();
        let db_receipt = prover
            .db
            .get_block_proof_by_hash(None, hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.journal, db_receipt.journal);
        assert_eq!(receipt, db_receipt);
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
        let hash = rpc.get_block_hash(height).await.unwrap();
        let genesis_hash = rpc.get_block_hash(0).await.unwrap();
        let (genesis_receipt, _) = prover.prove_till_hash(genesis_hash).await.unwrap();
        let block = rpc.get_block(&hash).await.unwrap();
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

    #[test]
    fn output_for_other_genesis_state_or_tip_is_rejected() {
        let genesis_state = ChainState::genesis_state();
        let header =
            CircuitBlockHeader::from(bitcoin::constants::genesis_block(Network::Regtest).header);
        let input = HeaderChainCircuitInput {
            method_id: [1; 8],
            prev_proof: HeaderChainPrevProofType::GenesisBlock(genesis_state.clone()),
            block_headers: vec![header.clone()],
        };
        let mut output = BlockHeaderCircuitOutput {
            method_id: input.method_id,
            genesis_state_hash: genesis_state.to_hash(),
            chain_state: genesis_state,
        };
        output.chain_state.block_height = 0;
        output.chain_state.best_block_hash = header.compute_block_hash();
        HeaderChainProver::check_output_matches_input(&input, &output).unwrap();

        let mut older_tip = output.clone();
        older_tip.chain_state = ChainState::genesis_state();
        assert!(HeaderChainProver::check_output_matches_input(&input, &older_tip).is_err());

        let mut other_genesis_state = output;
        other_genesis_state.genesis_state_hash = [0xab; 32];
        assert!(
            HeaderChainProver::check_output_matches_input(&input, &other_genesis_state).is_err()
        );
    }

    #[tokio::test]
    async fn work_only_output_matches_the_guest() {
        let guests = &bridge_circuit_host::guests::REGTEST;
        let header =
            CircuitBlockHeader::from(bitcoin::constants::genesis_block(Network::Regtest).header);
        let hcp_receipt = HeaderChainProver::prove_from_genesis(
            ChainState::genesis_state(),
            vec![header],
            &guests.header_chain,
            Backend::Mock,
        )
        .await
        .unwrap();
        let hcp: BlockHeaderCircuitOutput = borsh::from_slice(&hcp_receipt.journal.bytes).unwrap();
        assert_ne!(hcp.chain_state.total_work, [0; 32]);

        // Executing the guest as a compressed proof gives the same journal, without the slow
        // development Groth16 proof.
        let work_only = Guest {
            kind: ProofKind::Compressed,
            ..guests.work_only
        };
        let input = WorkOnlyCircuitInput {
            header_chain_circuit_output: hcp.clone(),
        };
        let receipt = prove(
            &work_only,
            GuestInput::new(&input)
                .unwrap()
                .with_assumption(&hcp_receipt)
                .unwrap(),
            Backend::Mock,
        )
        .await
        .unwrap();
        let output: WorkOnlyCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        assert_eq!(output, super::work_only_output(&hcp));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn prove_block_headers_genesis() {
        let genesis_state = ChainState::genesis_state();

        let receipt = HeaderChainProver::prove_from_genesis(
            genesis_state,
            vec![],
            &bridge_circuit_host::guests::REGTEST.header_chain,
            Backend::from_env().unwrap(),
        )
        .await
        .unwrap();

        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        println!("Proof journal output: {output:?}");

        assert_eq!(output.chain_state.block_height, u32::MAX); // No header yet; the first one wraps to 0
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

        let receipt = HeaderChainProver::prove_from_genesis(
            genesis_state,
            vec![],
            &prover.guests.header_chain,
            Backend::from_env().unwrap(),
        )
        .await
        .unwrap();

        let block_headers = mine_and_get_first_n_block_headers(rpc, prover.db.clone(), 3)
            .await
            .iter()
            .map(|header| CircuitBlockHeader::from(*header))
            .collect::<Vec<_>>();
        let receipt = HeaderChainProver::prove_block_headers(
            &prover.guests.header_chain,
            prover.backend,
            receipt,
            block_headers[0..2].to_vec(),
        )
        .await
        .unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();

        println!("Proof journal output: {output:?}");

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

        // No block is proven yet, so each proof starts from genesis.
        for i in (0..3).rev() {
            let hash = rpc.get_block_hash(i).await.unwrap();
            let (proof, _) = prover.prove_till_hash(hash).await.unwrap();
            let db_proof = db
                .get_block_proof_by_hash(None, hash)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.journal, db_proof.journal);

            let output: BlockHeaderCircuitOutput = borsh::from_slice(&proof.journal.bytes).unwrap();
            assert_eq!(
                output.genesis_state_hash,
                config.protocol_paramset().genesis_chain_state_hash
            );
            assert_eq!(u64::from(output.chain_state.block_height), i);
        }
        let hash = rpc.get_block_hash(5).await.unwrap();
        let (proof, _) = prover.prove_till_hash(hash).await.unwrap();
        let db_proof = db
            .get_block_proof_by_hash(None, hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(proof.journal, db_proof.journal);
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

        let hash = rpc.get_block_hash(2).await.unwrap();
        let (receipt, _) = prover.prove_till_hash(hash).await.unwrap();
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
        assert_eq!(receipt, get_receipt);

        // Try to get proof of the previous block that its heir is proven.
        let target_height = latest_proof.2 - 1;
        let target_hash = rpc.get_block_hash(target_height).await.unwrap();

        assert!(db
            .get_block_proof_by_hash(None, target_hash)
            .await
            .unwrap()
            .is_none());

        // get_header_chain_proof should calculate the proof for the block.
        let _receipt = prover.get_tip_header_chain_proof().await.unwrap();
    }
}
