//! # Prover
//!
//! Prover is responsible for preparing RiscZero header chain prover proofs.

use crate::{errors::BridgeError, header_chain_prover::HeaderChainProver};
use bitcoin::hashes::Hash;
use bitcoin_mock_rpc::RpcApiWrapper;
use circuits::header_chain::{
    BlockHeader, BlockHeaderCircuitOutput, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use lazy_static::lazy_static;
use risc0_zkvm::{compute_image_id, ExecutorEnv, Receipt};
use std::time::Duration;
use tokio::time::sleep;

// Prepare prover binary and calculate it's image id, before anything else.
const ELF: &[u8; 186232] = include_bytes!("../../../scripts/header-chain-guest");
lazy_static! {
    static ref IMAGE_ID: [u32; 8] = compute_image_id(ELF)
        .unwrap()
        .as_words()
        .try_into()
        .unwrap();
}

impl<R> HeaderChainProver<R>
where
    R: RpcApiWrapper,
{
    /// Prove a block.
    ///
    /// # Parameters
    ///
    /// - `prev_receipt`: Previous proof's receipt, if not genesis block
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
        // Prepare proof input.
        let (prev_proof, method_id) = match &prev_receipt {
            Some(receipt) => {
                let prev_output: BlockHeaderCircuitOutput =
                    borsh::from_slice(&receipt.journal.bytes)
                        .map_err(BridgeError::ProverDeSerializationError)?;
                let method_id = prev_output.method_id;

                (HeaderChainPrevProofType::PrevProof(prev_output), method_id)
            }
            None => (HeaderChainPrevProofType::GenesisBlock, *IMAGE_ID),
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
            .map_err(|e| BridgeError::ProverError(format!("Can't build environment: {}", e)))?;

        let prover = risc0_zkvm::default_prover();

        tracing::trace!("Proving started for block");
        let receipt = prover
            .prove(env, ELF)
            .map_err(|e| BridgeError::ProverError(format!("Error while running prover: {}", e)))?
            .receipt;

        tracing::debug!("Proof receipt: {:?}", receipt);

        Ok(receipt)
    }

    /// Starts a Tokio task that proves new blocks.
    ///
    /// TODO: Use `&self`.
    ///
    /// # Parameters
    ///
    /// - prover: [`ChainProver`] instance
    /// - rx: Receiver end for blockgazer
    #[tracing::instrument(skip_all)]
    pub async fn start_prover(prover: HeaderChainProver<R>) {
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

            sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        create_extended_rpc, extended_rpc::ExtendedRpc, header_chain_prover::HeaderChainProver,
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
        let headers = include_bytes!("../../../scripts/headers.bin");

        headers
            .chunks(80)
            .map(|header| BlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<BlockHeader>>()
    }

    #[tokio::test]
    #[serial_test::serial]
    // #[ignore = "Proving takes too much time, run only when necessary"]
    async fn prove_block_genesis() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

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
    // #[ignore = "Proving takes too much time, run only when necessary"]
    async fn prove_block_second() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

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
    // #[ignore = "Proving takes too much time, run only when necessary"]
    async fn save_and_get_proof() {
        let mut config = create_test_config_with_thread_name("test_config.toml", None).await;
        let rpc = create_extended_rpc!(config);
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();
        let block_headers = get_headers();

        // Prove genesis block.
        let receipt = prover.prove_block(None, vec![]).await.unwrap();
        let hash =
            BlockHash::from_raw_hash(Hash::from_slice(&block_headers[1].prev_block_hash).unwrap());
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
        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();

        prover.run();
        sleep(Duration::from_millis(1000)).await;

        // Mine a block and write genesis block's proof to database.
        rpc.mine_blocks(1).unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
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
