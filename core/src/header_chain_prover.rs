//! # Header Chain Prover

use crate::errors::ResultExt;
use crate::states::block_cache::BlockCache;
use crate::task::{IntoTask, Task, TaskExt, WithDelay};
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
use sqlx::Postgres;
use std::{
    fs::File,
    io::{BufReader, Read},
    time::Duration,
};
use thiserror::Error;
use tonic::async_trait;

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

#[derive(Debug, Error)]
pub enum HeaderChainProverError {
    #[error("Error while de/serializing object")]
    ProverDeSerializationError,
    #[error("No header chain proofs for hash {0}")]
    NoHeaderChainProof(BlockHash),

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

#[derive(Debug, Clone)]
pub struct HeaderChainProver {
    db: Database,
    network: bitcoin::Network,
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

    #[tracing::instrument(skip_all)]
    pub async fn check_for_new_unproven_blocks(
        &self,
    ) -> Result<Option<(BlockHash, Header, u32, Receipt)>, BridgeError> {
        let non_proved_block = self.db.get_non_proven_block(None).await;

        match non_proved_block {
            Ok(non_proved_block) => Ok(Some((
                non_proved_block.0,
                non_proved_block.1,
                non_proved_block
                    .2
                    .try_into()
                    .wrap_err("Can't convert i32 to u32")?,
                non_proved_block.3,
            ))),
            Err(BridgeError::DatabaseError(sqlx::Error::RowNotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn prove_block(
        &self,
        current_block_hash: BlockHash,
        current_block_header: Header,
        current_block_height: u32,
        previous_proof: Receipt,
    ) -> Result<Receipt, BridgeError> {
        tracing::info!(
            "Prover starts proving for block with hash {} and with height {}",
            current_block_hash,
            current_block_height
        );

        let header: CircuitBlockHeader = current_block_header.into();
        let receipt = self.prove_block_headers(Some(previous_proof), vec![header.clone()])?;

        self.db
            .set_block_proof(None, current_block_hash, receipt.clone())
            .await?;

        Ok(receipt)
    }
}

#[derive(Debug, Clone)]
pub struct HeaderChainProverClient {
    db: Database,
}

impl HeaderChainProverClient {
    pub async fn new(db: Database) -> Result<Self, HeaderChainProverError> {
        Ok(HeaderChainProverClient { db })
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

    /// Sets a new block to database, later to be proven.
    pub async fn set_new_block(
        &self,
        block_cache: &BlockCache,
        dbtx: Option<&mut sqlx::Transaction<'_, Postgres>>,
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
            .set_new_block(
                dbtx,
                block_hash,
                block_header,
                block_cache.block_height.into(),
            )
            .await?;

        Ok(())
    }
}

impl IntoTask for HeaderChainProver {
    type Task = WithDelay<HeaderChainProverTask>;

    fn into_task(self) -> Self::Task {
        HeaderChainProverTask { inner: self }.with_delay(Duration::from_secs(1))
    }
}

#[derive(Debug)]
pub struct HeaderChainProverTask {
    inner: HeaderChainProver,
}

#[async_trait]
impl Task for HeaderChainProverTask {
    type Output = bool;

    async fn run_once(&mut self) -> std::result::Result<Self::Output, BridgeError> {
        let unproven_block = self.inner.check_for_new_unproven_blocks().await?;

        let (current_block_hash, current_block_header, current_block_height, previous_proof) =
            if let Some(unproven_block) = unproven_block {
                unproven_block
            } else {
                return Ok(false);
            };

        let receipt = self
            .inner
            .prove_block(
                current_block_hash,
                current_block_header,
                current_block_height,
                previous_proof,
            )
            .await?;
        tracing::info!(
            "Receipt for block with hash {:?} and height with: {:?}: {:?}",
            current_block_hash,
            current_block_height,
            receipt
        );

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::builder::transaction::{ContractContext, TransactionType, TxHandler};
    use crate::citrea::mock::MockCitreaClient;
    use crate::database::{Database, DatabaseTransaction};
    use crate::errors::BridgeError;
    use crate::extended_rpc::ExtendedRpc;
    use crate::header_chain_prover::HeaderChainProver;
    use crate::header_chain_prover::HeaderChainProverClient;
    use crate::states::block_cache::BlockCache;
    use crate::states::{block_cache, Duty, Owner};
    use crate::task::manager::BackgroundTaskManager;
    use crate::task::IntoTask;
    use crate::test::common::*;
    use crate::verifier::VerifierServer;
    use bitcoin::{hashes::Hash, BlockHash};
    use bitcoincore_rpc::RpcApi;
    use borsh::BorshDeserialize;
    use risc0_to_bitvm2_core::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
    use risc0_zkvm::Receipt;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tonic::async_trait;

    // Define an Owner for testing BackgroundTaskManager
    #[derive(Debug, Clone)]
    struct TestOwner;

    #[async_trait]
    impl Owner for TestOwner {
        const OWNER_TYPE: &'static str = "test_owner";

        async fn handle_duty(&self, _duty: Duty) -> Result<(), BridgeError> {
            // For testing purposes, just return OK
            Ok(())
        }

        async fn create_txhandlers(
            &self,
            _tx_type: TransactionType,
            _contract_context: ContractContext,
        ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
            // Return empty BTreeMap for testing
            Ok(BTreeMap::new())
        }

        async fn handle_finalized_block(
            &self,
            _dbtx: DatabaseTransaction<'_, '_>,
            _block_id: u32,
            _block_height: u32,
            _block_cache: Arc<block_cache::BlockCache>,
            _light_client_proof_wait_interval_secs: Option<u32>,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
    }

    /// Mines `block_num` amount of blocks (if not already mined) and returns
    /// the first `block_num` block headers in blockchain.
    async fn mine_and_get_first_n_block_headers(
        rpc: ExtendedRpc,
        db: Database,
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

            let _ignore_errors = db.set_new_block(None, hash, header, i).await;
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
        let db = Database::new(&config).await.unwrap();

        // First block's assumption will be added to db: Make sure block exists
        // too.
        rpc.mine_blocks(1).await.unwrap();
        let _prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();
        let prover_client = HeaderChainProverClient::new(db).await.unwrap();

        // Test assumption is for block 0.
        let hash = rpc.client.get_block_hash(0).await.unwrap();
        let _should_not_panic = prover_client.get_header_chain_proof(hash).await.unwrap();

        let wrong_hash = BlockHash::from_raw_hash(Hash::from_slice(&[0x45; 32]).unwrap());
        assert_ne!(wrong_hash, hash);
        assert!(prover_client
            .get_header_chain_proof(wrong_hash)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn prove_a_block_from_database() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();
        let prover_client = HeaderChainProverClient::new(db).await.unwrap();

        // Check if `HeaderChainProver::new` added the assumption.
        let previous_receipt =
            Receipt::try_from_slice(include_bytes!("../tests/data/first_1.bin")).unwrap();
        let height = 0;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let read_recipt = prover_client.get_header_chain_proof(hash).await.unwrap();
        assert_eq!(previous_receipt.journal, read_recipt.journal);

        // Set up the next non proven block.
        let height = 1;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let block = rpc.client.get_block(&hash).await.unwrap();
        let header = block.header;
        prover
            .db
            .set_new_block(None, hash, header, height)
            .await
            .unwrap();

        let receipt = prover
            .prove_block(hash, header, height.try_into().unwrap(), previous_receipt)
            .await
            .unwrap();

        let read_recipt = prover_client.get_header_chain_proof(hash).await.unwrap();
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

        let block_headers = mine_and_get_first_n_block_headers(rpc, prover.db.clone(), 3).await;
        let receipt = prover
            .prove_block_headers(Some(receipt), block_headers[0..2].to_vec())
            .unwrap();
        let output: BlockHeaderCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();

        println!("Proof journal output: {:?}", output);

        assert_eq!(output.chain_state.block_height, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_for_new_blocks_and_prove() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let prover = HeaderChainProver::new(&config, rpc.clone()).await.unwrap();
        let prover_client: HeaderChainProverClient =
            HeaderChainProverClient::new(db.clone()).await.unwrap();

        let number_of_blocks_to_prove = 5;
        let _block_headers =
            mine_and_get_first_n_block_headers(rpc.clone(), db.clone(), number_of_blocks_to_prove)
                .await;

        // Prove blocks after the first one. Because the first one has
        // an assumption that is provided from the bridge config.
        for i in 1..number_of_blocks_to_prove {
            let non_proven_block = prover
                .check_for_new_unproven_blocks()
                .await
                .unwrap()
                .unwrap();
            assert_eq!(non_proven_block.2, i as u32);

            let previous_block_hash = rpc.client.get_block_hash(i - 1).await.unwrap();
            let current_block_hash = rpc.client.get_block_hash(i).await.unwrap();
            let current_block_header = rpc
                .client
                .get_block_header(&current_block_hash)
                .await
                .unwrap();
            let previous_proof = prover_client
                .get_header_chain_proof(previous_block_hash)
                .await
                .unwrap();

            let receipt = prover
                .prove_block(
                    current_block_hash,
                    current_block_header,
                    i.try_into().unwrap(),
                    previous_proof,
                )
                .await
                .unwrap();

            let db_receipt = db
                .get_block_proof_by_hash(None, current_block_hash)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(receipt.journal, db_receipt.journal);
            assert_eq!(receipt.metadata, db_receipt.metadata);
        }
    }

    #[tokio::test]
    async fn start_task_and_fetch_proofs() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let header_chain_prover = HeaderChainProver::new(&config, rpc.clone_inner().await.unwrap())
            .await
            .unwrap();
        let mut background_tasks: BackgroundTaskManager<TestOwner> =
            BackgroundTaskManager::default();
        background_tasks.loop_and_monitor(header_chain_prover.into_task());

        let height = 1;
        let hash = rpc.client.get_block_hash(height).await.unwrap();
        let block = rpc.client.get_block(&hash).await.unwrap();

        let hcp_client = HeaderChainProverClient::new(Database::new(&config).await.unwrap())
            .await
            .unwrap();

        let block_cache = BlockCache {
            block_height: height.try_into().unwrap(),
            block: Some(block),
            txids: Default::default(),
            spent_utxos: Default::default(),
        };
        hcp_client.set_new_block(&block_cache, None).await.unwrap();

        poll_until_condition(
            async || Ok(hcp_client.get_header_chain_proof(hash).await.is_ok()),
            None,
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    }

    #[ignore = "Proving blocks one by one is very slow and this test should be enabled when proving in batches is implemented."]
    #[tokio::test]
    async fn verifier_new_check_header_chain_proof() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        // Save initial blocks, because VerifierServer won't.
        let count = rpc.client.get_block_count().await.unwrap();
        tracing::info!("Block count: {}", count);
        for i in 1..count {
            let hash = rpc.client.get_block_hash(i).await.unwrap();
            let block = rpc.client.get_block(&hash).await.unwrap();

            db.set_new_block(None, block.block_hash(), block.header, i)
                .await
                .unwrap();
        }

        let verifier = VerifierServer::<MockCitreaClient>::new(config)
            .await
            .unwrap();
        rpc.mine_blocks(10).await.unwrap();

        // Aim for a proved block that is added to the database by the verifier.
        let height = rpc.client.get_block_count().await.unwrap() - 7;
        let hash = rpc.client.get_block_hash(height).await.unwrap();

        poll_until_condition(
            async || {
                Ok(verifier
                    .verifier
                    .header_chain_prover
                    .get_header_chain_proof(hash)
                    .await
                    .is_ok())
            },
            Some(Duration::from_secs(60 * 10)),
            Some(Duration::from_secs(1)),
        )
        .await
        .unwrap();
    }
}
