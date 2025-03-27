//! # Header Chain Prover

use crate::errors::ResultExt;
use crate::{
    config::BridgeConfig,
    database::Database,
    errors::{BridgeError, ErrorExt},
    extended_rpc::ExtendedRpc,
};
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
    time::Duration,
};
use thiserror::Error;
use tokio::time::sleep;

// Prepare prover binary and calculate it's image id, before anything else.
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

#[derive(Debug, Clone)]
pub struct HeaderChainProver {
    db: Database,
    network: bitcoin::Network,
}

#[derive(Debug, Error)]
pub enum HeaderChainProverError {
    #[error("Error while de/serializing object")]
    ProverDeSerializationError,
    #[error("No header chain proofs for hash {0}")]
    NoHeaderChainProof(BlockHash),

    #[error(transparent)]
    Other(#[from] eyre::Report),
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
            // Ignore error if block entry is in database already.
            let _ = db
                .set_new_block(
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
            network: config.protocol_paramset().network,
        })
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
        match self.db.get_block_proof_by_hash(None, hash).await? {
            Some(r) => Ok(r),
            None => Err(HeaderChainProverError::NoHeaderChainProof(hash).into()),
        }
    }

    /// Starts a background task that syncs current database to active
    /// blockchain and does proving.
    #[tracing::instrument]
    pub fn run(&self) {
        let prover = HeaderChainProver::start_prover(self.clone());

        tokio::spawn(async move {
            tokio::join!(prover);
        });
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

        tracing::trace!("Proving started for block");
        let receipt = prover.prove(env, elf).map_err(|e| eyre::eyre!(e))?.receipt;

        tracing::debug!("Proof receipt: {:?}", receipt);

        Ok(receipt)
    }

    /// Starts an async task that checks for non proved blocks and proves them.
    ///
    /// # Parameters
    ///
    /// - prover: [`ChainProver`] instance
    #[tracing::instrument(skip_all)]
    pub async fn start_prover(prover: HeaderChainProver) {
        loop {
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

                let header: CircuitBlockHeader = current_block_header.into();
                let receipt =
                    prover.prove_block_headers(Some(previous_proof), vec![header.clone()]);

                match receipt {
                    Ok(receipt) => {
                        if let Err(e) = prover
                            .db
                            .set_block_proof(None, current_block_hash, receipt)
                            .await
                        {
                            tracing::error!("Can't save proof for header {:?}: {}", header, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Can't prove for header {:?}: {}", header, e)
                    }
                };
            }

            sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::extended_rpc::ExtendedRpc;
    use crate::header_chain_prover::HeaderChainProver;
    use crate::test::common::*;
    use bitcoin::{
        block::{Header, Version},
        CompactTarget, TxMerkleNode,
    };
    use bitcoin::{hashes::Hash, BlockHash};
    use bitcoincore_rpc::RpcApi;
    use borsh::BorshDeserialize;
    use risc0_to_bitvm2_core::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
    use risc0_zkvm::Receipt;
    use std::time::Duration;
    use tokio::time::sleep;

    async fn mine_and_get_first_n_block_headers(
        rpc: ExtendedRpc,
        block_num: u64,
    ) -> Vec<CircuitBlockHeader> {
        let height = rpc.client.get_block_count().await.unwrap();
        if height < block_num {
            rpc.mine_blocks(block_num - height).await.unwrap();
        }

        let mut headers = Vec::new();
        for i in 0..block_num {
            let hash = rpc.client.get_block_hash(i).await.unwrap();
            let header = rpc.client.get_block_header(&hash).await.unwrap();

            headers.push(CircuitBlockHeader::from(header));
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
    async fn start_header_chain_prover() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();
        prover.run();
        sleep(Duration::from_secs(1)).await;

        // Mine a block and write genesis block's proof to database.
        rpc.mine_blocks(1).await.unwrap();
        let receipt = Receipt::try_from_slice(include_bytes!("../tests/data/first_1.bin")).unwrap();
        prover
            .db
            .set_block_proof(None, BlockHash::all_zeros(), receipt.clone())
            .await
            .unwrap();

        // Set up non proven block.
        let height = 1;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let block = rpc.client.get_block(&hash).await.unwrap();
        let header = block.header;
        prover
            .db
            .set_new_block(None, hash, header, height)
            .await
            .unwrap();

        poll_until_condition(
            async || Ok(prover.get_header_chain_proof(hash).await.is_ok()),
            Some(Duration::from_secs(180)),
            None,
        )
        .await
        .unwrap();
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

        let block_headers = mine_and_get_first_n_block_headers(rpc, 3).await;
        let receipt = prover
            .prove_block_headers(Some(receipt), block_headers[0..2].to_vec())
            .unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();

        println!("Proof journal output: {:?}", output);

        assert_eq!(output.chain_state.block_height, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn save_and_get_proof() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();
        let block_headers = mine_and_get_first_n_block_headers(rpc, 3).await;

        // Prove genesis block.
        let receipt = prover.prove_block_headers(None, vec![]).unwrap();
        let hash =
            BlockHash::from_raw_hash(Hash::from_slice(&block_headers[1].prev_block_hash).unwrap());
        let header: Header = block_headers[0].clone().into();
        let _ = prover.db.set_new_block(None, hash, header, 0).await; // TODO: Unwrapping this causes errors.
        prover
            .db
            .set_block_proof(None, hash, receipt.clone())
            .await
            .unwrap();
        let database_receipt = prover.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(receipt.journal, database_receipt.journal);
        assert_eq!(receipt.metadata, database_receipt.metadata);

        // Prove second block.
        let receipt = prover
            .prove_block_headers(Some(receipt), block_headers[0..2].to_vec())
            .unwrap();
        let hash =
            BlockHash::from_raw_hash(Hash::from_slice(&block_headers[2].prev_block_hash).unwrap());
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
            .set_new_block(None, hash, header, 0)
            .await
            .unwrap();

        prover
            .db
            .set_block_proof(None, hash, receipt.clone())
            .await
            .unwrap();
        let database_receipt2 = prover.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(receipt.journal, database_receipt2.journal);
        assert_eq!(receipt.metadata, database_receipt2.metadata);
        assert_ne!(receipt.journal, database_receipt.journal);
    }
}
