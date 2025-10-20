//! # Header Chain Prover Related Database Operations
//!
//! This module includes database functions which are mainly used by the header
//! chain prover.

use super::{
    wrapper::{BlockHashDB, BlockHeaderDB},
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx, extended_bitcoin_rpc::ExtendedBitcoinRpc};
use bitcoin::{
    block::{self, Header},
    BlockHash,
};
use eyre::Context;
use risc0_zkvm::Receipt;

impl Database {
    /// Adds a new finalized block to the database, later to be updated with a
    /// proof.
    pub async fn save_unproven_finalized_block(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: block::BlockHash,
        block_header: block::Header,
        block_height: u64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
                "INSERT INTO header_chain_proofs (block_hash, block_header, prev_block_hash, height) VALUES ($1, $2, $3, $4)
                ON CONFLICT (block_hash) DO NOTHING",
            )
            .bind(BlockHashDB(block_hash)).bind(BlockHeaderDB(block_header)).bind(BlockHashDB(block_header.prev_blockhash)).bind(block_height as i64);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Collect block info from rpc and save it to hcp table.
    async fn save_block_infos_within_range(
        &self,
        mut dbtx: Option<DatabaseTransaction<'_, '_>>,
        rpc: &ExtendedBitcoinRpc,
        height_start: u32,
        height_end: u32,
    ) -> Result<(), BridgeError> {
        const BATCH_SIZE: u32 = 100;

        for batch_start in (height_start..=height_end).step_by(BATCH_SIZE as usize) {
            let batch_end = std::cmp::min(batch_start + BATCH_SIZE - 1, height_end);

            // Collect all block headers in this batch
            let mut block_infos = Vec::with_capacity((batch_end - batch_start + 1) as usize);
            for height in batch_start..=batch_end {
                let (block_hash, block_header) =
                    rpc.get_block_info_by_height(height as u64).await?;
                block_infos.push((block_hash, block_header, height));
            }

            // Save all blocks in this batch
            let mut db_tx = match dbtx {
                Some(_) => None, // no nested transaction
                None => Some(self.begin_transaction().await?),
            };
            for (block_hash, block_header, height) in block_infos {
                self.save_unproven_finalized_block(
                    db_tx.as_mut().or(dbtx.as_deref_mut()),
                    block_hash,
                    block_header,
                    height as u64,
                )
                .await?;
            }
            if let Some(db_tx) = db_tx {
                db_tx.commit().await?;
            }
        }
        Ok(())
    }

    /// This function assumes there are no blocks or some contiguous blocks starting from 0 already in the table.
    /// Saves the block hashes and headers until given height(exclusive)
    /// as they are needed for spv and hcp proofs.
    pub async fn fetch_and_save_missing_blocks(
        &self,
        mut dbtx: Option<DatabaseTransaction<'_, '_>>,
        rpc: &ExtendedBitcoinRpc,
        genesis_height: u32,
        until_height: u32,
    ) -> Result<(), BridgeError> {
        if until_height == 0 {
            return Ok(());
        }
        let max_height = self
            .get_latest_finalized_block_height(dbtx.as_deref_mut())
            .await?;
        if let Some(max_height) = max_height {
            if max_height < until_height as u64 {
                self.save_block_infos_within_range(
                    dbtx.as_deref_mut(),
                    rpc,
                    max_height as u32 + 1,
                    until_height - 1,
                )
                .await?;
            }
        } else {
            tracing::debug!("Saving blocks from start until {}", until_height);
            self.save_block_infos_within_range(dbtx, rpc, genesis_height, until_height - 1)
                .await?;
        }
        Ok(())
    }

    /// Returns block hash and header for a given range of heights. Ranges are
    /// inclusive on both ends.
    pub async fn get_block_info_from_range(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<(BlockHash, Header)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header
            FROM header_chain_proofs
            WHERE height >= $1 AND height <= $2
            ORDER BY height ASC;",
        )
        .bind(start_height as i64)
        .bind(end_height as i64);

        let result: Vec<(BlockHashDB, BlockHeaderDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        let result = result
            .iter()
            .map(|result| (result.0 .0, result.1 .0))
            .collect::<Vec<_>>();

        Ok(result)
    }

    /// Returns the previous block hash and header for a given block hash.
    ///
    /// # Returns
    ///
    /// Returns `None` if the block hash is not found.
    ///
    /// - [`BlockHash`] - Previous block's hash
    /// - [`Header`] - Block's header
    /// - [`u32`] - Block's height
    pub async fn get_block_info_from_hash_hcp(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: BlockHash,
    ) -> Result<Option<(BlockHash, Header, u32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT prev_block_hash, block_header, height FROM header_chain_proofs WHERE block_hash = $1",
        )
        .bind(BlockHashDB(block_hash));
        let result: Option<(BlockHashDB, BlockHeaderDB, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        result
            .map(|result| -> Result<(BlockHash, Header, u32), BridgeError> {
                let height = result.2.try_into().wrap_err("Can't convert i64 to u32")?;
                Ok((result.0 .0, result.1 .0, height))
            })
            .transpose()
    }

    /// Returns latest finalized blocks height from the database.
    pub async fn get_latest_finalized_block_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u64>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM header_chain_proofs ORDER BY height DESC LIMIT 1;");

        let result: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result.map(|height| height.0 as u64))
    }

    /// Gets the first finalized block after the latest proven block (i.e. proof != null).
    /// This block will be the candidate block for the prover.
    ///
    /// # Returns
    ///
    /// Returns `None` if either no proved blocks are exists or blockchain tip
    /// is already proven.
    ///
    /// - [`BlockHash`] - Hash of the block
    /// - [`Header`] - Header of the block
    /// - [`u64`] - Height of the block
    /// - [`Receipt`] - Previous block's proof
    pub async fn get_next_unproven_block(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<(BlockHash, Header, u64, Receipt)>, BridgeError> {
        let latest_proven_block_height = self
            .get_latest_proven_block_info(tx.as_deref_mut())
            .await?
            .map(|(_, _, height)| height);

        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                    h1.block_header,
                    h1.height,
                    h2.proof
                FROM header_chain_proofs h1
                JOIN header_chain_proofs h2 ON h1.prev_block_hash = h2.block_hash
                WHERE h2.proof IS NOT NULL AND h1.proof IS NULL
                ORDER BY h1.height DESC
                LIMIT 1",
        );

        let result: Option<(BlockHashDB, BlockHeaderDB, i64, Vec<u8>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        let result = match result {
            Some(result) => {
                let receipt: Receipt =
                    borsh::from_slice(&result.3).wrap_err(BridgeError::BorshError)?;
                let height: u64 = result.2.try_into().wrap_err("Can't convert i64 to u64")?;
                Some((result.0 .0, result.1 .0, height, receipt))
            }
            None => None,
        };

        // If the latest block is already proven, return None instead of the old
        // unproven block.
        if let (Some((_, _, height, _)), Some(latest_proven_block_height)) =
            (&result, latest_proven_block_height)
        {
            if *height < latest_proven_block_height {
                return Ok(None);
            }
        }

        Ok(result)
    }

    /// Gets the newest n number of block's info that their previous block has
    /// proven before. These blocks will be the candidate blocks for the prover.
    ///
    /// # Returns
    ///
    /// Returns `None` if either no proved blocks are exists or blockchain tip
    /// is already proven.
    ///
    /// - [`BlockHash`] - Hash of last block in the batch
    /// - [`Header`] - Headers of the blocks
    /// - [`u64`] - Height of the last block in the batch
    /// - [`Receipt`] - Previous block's proof
    pub async fn get_next_n_non_proven_block(
        &self,
        count: u32,
    ) -> Result<Option<(Vec<(BlockHash, Header, u64)>, Receipt)>, BridgeError> {
        let Some(next_non_proven_block) = self.get_next_unproven_block(None).await? else {
            return Ok(None);
        };

        let query = sqlx::query_as(
            "SELECT block_hash,
                    block_header,
                    height
                FROM header_chain_proofs
                WHERE height >= $1
                ORDER BY height ASC
                LIMIT $2;",
        )
        .bind(next_non_proven_block.2 as i64)
        .bind(count as i64);
        let result: Vec<(BlockHashDB, BlockHeaderDB, i64)> = execute_query_with_tx!(
            self.connection,
            None::<DatabaseTransaction>,
            query,
            fetch_all
        )?;

        let blocks = result
            .iter()
            .map(|result| {
                let height = result.2.try_into().wrap_err("Can't convert i64 to u64")?;

                Ok((result.0 .0, result.1 .0, height))
            })
            .collect::<Result<Vec<_>, BridgeError>>()?;

        // If not yet enough entries are found, return `None`.
        if blocks.len() != count as usize {
            tracing::error!(
                "Non proven block count: {}, required count: {}",
                blocks.len(),
                count
            );
            return Ok(None);
        }

        Ok(Some((blocks, next_non_proven_block.3)))
    }

    /// Gets the latest block's info that it's proven.
    ///
    /// # Returns
    ///
    /// Returns `None` if no block is proven.
    ///
    /// - [`BlockHash`] - Hash of the block
    /// - [`Header`] - Header of the block
    /// - [`u64`] - Height of the block
    pub async fn get_latest_proven_block_info(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<(BlockHash, Header, u64)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header, height
            FROM header_chain_proofs
            WHERE proof IS NOT NULL
            ORDER BY height DESC
            LIMIT 1;",
        );

        let result: Option<(BlockHashDB, BlockHeaderDB, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        let result = match result {
            Some(result) => {
                let height = result.2.try_into().wrap_err("Can't convert i64 to u64")?;
                Some((result.0 .0, result.1 .0, height))
            }
            None => None,
        };

        Ok(result)
    }

    /// Gets the latest block's info that it's proven and has height less than or equal to the given height.
    ///
    /// # Returns
    ///
    /// Returns `None` if no block is proven.
    ///
    /// - [`BlockHash`] - Hash of the block
    /// - [`Header`] - Header of the block
    /// - [`u64`] - Height of the block
    pub async fn get_latest_proven_block_info_until_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u32,
    ) -> Result<Option<(BlockHash, Header, u64)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header, height
            FROM header_chain_proofs
            WHERE proof IS NOT NULL AND height <= $1
            ORDER BY height DESC
            LIMIT 1;",
        )
        .bind(height as i64);

        let result: Option<(BlockHashDB, BlockHeaderDB, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        let result = match result {
            Some(result) => {
                let height = result.2.try_into().wrap_err("Can't convert i64 to u64")?;
                Some((result.0 .0, result.1 .0, height))
            }
            None => None,
        };

        Ok(result)
    }

    /// Sets an existing block's (in database) proof by referring to it by it's
    /// hash.
    pub async fn set_block_proof(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        hash: block::BlockHash,
        proof: Receipt,
    ) -> Result<(), BridgeError> {
        let proof = borsh::to_vec(&proof).wrap_err(BridgeError::BorshError)?;

        let query = sqlx::query("UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2")
            .bind(proof)
            .bind(BlockHashDB(hash));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets a block's proof by referring to it by it's hash.
    pub async fn get_block_proof_by_hash(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        hash: block::BlockHash,
    ) -> Result<Option<Receipt>, BridgeError> {
        let query = sqlx::query_as("SELECT proof FROM header_chain_proofs WHERE block_hash = $1")
            .bind(BlockHashDB(hash));

        let receipt: (Option<Vec<u8>>,) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        let receipt = match receipt.0 {
            Some(r) => r,
            None => return Ok(None),
        };

        let receipt: Receipt = borsh::from_slice(&receipt).wrap_err(BridgeError::BorshError)?;

        Ok(Some(receipt))
    }
}

#[cfg(test)]
mod tests {
    use crate::database::Database;
    use crate::test::common::*;
    use bitcoin::block::{self, Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use borsh::BorshDeserialize;
    use risc0_zkvm::Receipt;

    #[tokio::test]
    async fn save_get_new_block() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        assert!(db
            .get_latest_finalized_block_height(None)
            .await
            .unwrap()
            .is_none());

        // Set first block, so that get_non_proven_block won't return error.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 1;
        db.save_unproven_finalized_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            db.get_latest_finalized_block_height(None)
                .await
                .unwrap()
                .unwrap(),
            height
        );
        let receipt = Receipt::try_from_slice(include_bytes!("../test/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash, receipt).await.unwrap();
        let latest_proven_block = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest_proven_block.0, block_hash);
        assert_eq!(latest_proven_block.1, block.header);
        assert_eq!(latest_proven_block.2, height);

        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1,
                bits: CompactTarget::default(),
                nonce: 1,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 2;
        db.save_unproven_finalized_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        let (read_block_hash, read_block_header, _, _) =
            db.get_next_unproven_block(None).await.unwrap().unwrap();
        assert_eq!(block_hash, read_block_hash);
        assert_eq!(block.header, read_block_header);
    }

    #[tokio::test]
    pub async fn save_get_block_proof() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        // Save dummy block.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 0x45;
        db.save_unproven_finalized_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        // Requesting proof for an existing block without a proof should
        // return `None`.
        let read_receipt = db.get_block_proof_by_hash(None, block_hash).await.unwrap();
        assert!(read_receipt.is_none());

        // Update it with a proof.
        let receipt = Receipt::try_from_slice(include_bytes!("../test/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash, receipt.clone())
            .await
            .unwrap();

        let read_receipt = db
            .get_block_proof_by_hash(None, block_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.journal, read_receipt.journal);
        assert_eq!(receipt.metadata, read_receipt.metadata);
    }

    #[tokio::test]
    pub async fn get_non_proven_block() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());
        assert!(db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .is_none());

        let base_height = 0x45;

        // Save initial block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = base_height;
        db.save_unproven_finalized_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());
        assert!(db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .is_none());

        // Save second block with a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 1,
            },
            txdata: vec![],
        };
        let block_hash1 = block.block_hash();
        let height1 = base_height + 1;
        db.save_unproven_finalized_block(None, block_hash1, block.header, height1)
            .await
            .unwrap();
        let receipt = Receipt::try_from_slice(include_bytes!("../test/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());
        let latest_proven_block = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest_proven_block.0, block_hash1);
        assert_eq!(latest_proven_block.1, block.header);
        assert_eq!(latest_proven_block.2 as u64, height1);

        // Save third block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash1,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 3,
            },
            txdata: vec![],
        };
        let block_hash2 = block.block_hash();
        let height2 = base_height + 2;
        db.save_unproven_finalized_block(None, block_hash2, block.header, height2)
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return third block's details.
        let res = db.get_next_unproven_block(None).await.unwrap().unwrap();
        assert_eq!(res.0, block_hash2);
        assert_eq!(res.2 as u64, height2);

        // Save fourth block with a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash1,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 4,
            },
            txdata: vec![],
        };
        let block_hash3 = block.block_hash();
        let height3 = base_height + 3;
        db.save_unproven_finalized_block(None, block_hash3, block.header, height3)
            .await
            .unwrap();
        db.set_block_proof(None, block_hash3, receipt.clone())
            .await
            .unwrap();

        // This time, `get_non_proven_block` shouldn't return any block because latest is proved.
        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());

        // Save fifth block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash1,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 5,
            },
            txdata: vec![],
        };
        let block_hash4 = block.block_hash();
        let height4 = base_height + 4;
        db.save_unproven_finalized_block(None, block_hash4, block.header, height4)
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return fifth block's details.
        let res = db.get_next_unproven_block(None).await.unwrap().unwrap();
        assert_eq!(res.2 as u64, height4);
        assert_eq!(res.0, block_hash4);
    }

    #[tokio::test]
    pub async fn get_non_proven_blocks() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        assert!(db
            .get_next_n_non_proven_block(batch_size)
            .await
            .unwrap()
            .is_none());
        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());
        assert!(db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .is_none());

        let mut height = 0x45;

        // Save initial block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        db.save_unproven_finalized_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db
            .get_next_n_non_proven_block(batch_size)
            .await
            .unwrap()
            .is_none());
        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());
        assert!(db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .is_none());

        // Save second block with a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 1,
            },
            txdata: vec![],
        };
        let block_hash1 = block.block_hash();
        height += 1;
        db.save_unproven_finalized_block(None, block_hash1, block.header, height)
            .await
            .unwrap();
        let receipt = Receipt::try_from_slice(include_bytes!("../test/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db
            .get_next_n_non_proven_block(batch_size)
            .await
            .unwrap()
            .is_none());
        assert!(db.get_next_unproven_block(None).await.unwrap().is_none());
        let latest_proven_block = db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest_proven_block.0, block_hash1);
        assert_eq!(latest_proven_block.1, block.header);
        assert_eq!(latest_proven_block.2 as u64, height);

        // Save next blocks without a proof.
        let mut blocks: Vec<(BlockHash, u32)> = Vec::new();
        let mut prev_block_hash = block_hash1;
        for i in 0..batch_size {
            let block = block::Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: prev_block_hash,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0x1F,
                    bits: CompactTarget::default(),
                    nonce: 0x45 + 2 + i,
                },
                txdata: vec![],
            };
            let block_hash = block.block_hash();

            height += 1;
            prev_block_hash = block_hash;

            db.save_unproven_finalized_block(None, block_hash, block.header, height)
                .await
                .unwrap();

            blocks.push((block_hash, height.try_into().unwrap()));
        }

        // This time, `get_non_proven_block` should return third block's details.
        let res = db
            .get_next_n_non_proven_block(batch_size)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(res.0.len(), batch_size as usize);
        for i in 0..batch_size {
            let i = i as usize;
            assert_eq!(res.0[i].2, blocks[i].1 as u64);
            assert_eq!(res.0[i].0, blocks[i].0);
        }
    }

    #[tokio::test]
    async fn get_block_info_from_range() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        let start_height = 0x45;
        let end_height = 0x55;
        assert!(db
            .get_block_info_from_range(None, start_height, end_height)
            .await
            .unwrap()
            .is_empty());

        let mut infos = Vec::new();

        for height in start_height..end_height {
            let block = block::Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0x1F,
                    bits: CompactTarget::default(),
                    nonce: height as u32,
                },
                txdata: vec![],
            };
            let block_hash = block.block_hash();

            db.save_unproven_finalized_block(None, block_hash, block.header, height)
                .await
                .unwrap();
            infos.push((block_hash, block.header));

            let res = db
                .get_block_info_from_range(None, start_height, height)
                .await
                .unwrap();
            assert_eq!(res.len() as u64, height - start_height + 1);
            assert_eq!(infos, res);
        }
    }

    #[tokio::test]
    async fn get_latest_proven_block_info() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let proof = Receipt::try_from_slice(include_bytes!("../test/data/first_1.bin")).unwrap();

        assert!(db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .is_none());

        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let mut block_hash = block.block_hash();
        let mut height = 0x45;
        db.save_unproven_finalized_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db
            .get_latest_proven_block_info(None)
            .await
            .unwrap()
            .is_none());

        for i in 0..3 {
            let block = block::Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: block_hash,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0x1F,
                    bits: CompactTarget::default(),
                    nonce: 0x45 + i,
                },
                txdata: vec![],
            };
            block_hash = block.block_hash();
            height += 1;

            db.save_unproven_finalized_block(None, block_hash, block.header, height)
                .await
                .unwrap();
            db.set_block_proof(None, block_hash, proof.clone())
                .await
                .unwrap();

            let latest_proven_block = db
                .get_latest_proven_block_info(None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(latest_proven_block.0, block_hash);
            assert_eq!(latest_proven_block.1, block.header);
            assert_eq!(latest_proven_block.2, height);
        }
    }
}
