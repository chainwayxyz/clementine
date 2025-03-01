//! # Header Chain Prover
//!
//! Fetches latest blocks from active blockchain and prepares proves for them.

use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError, extended_rpc::ExtendedRpc,
};
use bitcoin::{hashes::Hash, BlockHash};
use bitcoincore_rpc::RpcApi;
use risc0_to_bitvm2_core::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::Receipt;
use std::{
    fs::File,
    io::{BufReader, Read},
};

mod blockgazer;
mod prover;

#[derive(Debug, Clone)]
pub struct HeaderChainProver {
    rpc: ExtendedRpc,
    db: Database,
    network: bitcoin::Network,
}

impl HeaderChainProver {
    pub async fn new(config: &BridgeConfig, rpc: ExtendedRpc) -> Result<Self, BridgeError> {
        let db = Database::new(config).await?;

        if let Some(proof_file) = &config.header_chain_proof_path {
            tracing::trace!("Starting prover with assumption file {:?}.", proof_file);
            let file = File::open(proof_file)
                .map_err(|e| BridgeError::WrongProofAssumption(proof_file.clone(), e))?;

            let mut reader = BufReader::new(file);
            let mut assumption = Vec::new();
            reader
                .read_to_end(&mut assumption)
                .map_err(BridgeError::BorshError)?; // TODO: Not borsh.

            let proof: Receipt =
                borsh::from_slice(&assumption).map_err(BridgeError::ProverDeSerializationError)?;
            let proof_output: BlockHeaderCircuitOutput = borsh::from_slice(&proof.journal.bytes)
                .map_err(BridgeError::ProverDeSerializationError)?;

            // Create block entry, if not exists.
            let block_hash = BlockHash::from_raw_hash(Hash::from_slice(
                &proof_output.chain_state.best_block_hash,
            )?);
            let block_header = rpc.client.get_block_header(&block_hash).await?;
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
            db.set_block_proof(None, block_hash, proof).await?;
        };

        Ok(HeaderChainProver {
            rpc,
            db,
            network: config.network,
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
            None => Err(BridgeError::NoHeaderChainProof(hash)),
        }
    }

    /// Starts a background task that syncs current database to active
    /// blockchain and does proving.
    #[tracing::instrument]
    pub fn run(&self) {
        let block_gazer = HeaderChainProver::start_blockgazer(self.clone());
        let prover = HeaderChainProver::start_prover(self.clone());

        tokio::spawn(async move {
            tokio::join!(block_gazer, prover);
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::header_chain_prover::HeaderChainProver;
    use crate::test::common::*;
    use bitcoin::{hashes::Hash, BlockHash};
    use bitcoincore_rpc::RpcApi;
    use borsh::BorshDeserialize;
    use risc0_zkvm::Receipt;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn new() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let _should_not_panic = HeaderChainProver::new(&config, rpc).await.unwrap();
    }

    #[tokio::test]

    async fn new_with_proof_assumption() {
        let mut config = create_test_config_with_thread_name(None).await;
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
    #[ignore = "This test is very host dependent and needs a human observer"]
    async fn start_header_chain_prover() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();

        prover.run();
        sleep(Duration::from_secs(1)).await;

        // Mine a block and write genesis block's proof to database.
        rpc.mine_blocks(1).await.unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        prover
            .db
            .set_block_proof(None, BlockHash::all_zeros(), receipt.clone())
            .await
            .unwrap();

        let hash = rpc.client.get_block_hash(1).await.unwrap();
        loop {
            if let Ok(proof) = prover.get_header_chain_proof(hash).await {
                println!("Second block's proof is {:?}", proof);
                break;
            }

            println!("Waiting for proof to be written to database for second block...");
            sleep(Duration::from_secs(1)).await;
        }
    }
}
