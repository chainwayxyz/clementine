//! # Header Chain Prover Related Database Operations
//!
//! This module includes database functions which are mainly used by the header
//! chain prover.

use super::{
    wrapper::{BlockHashDB, BlockHeaderDB},
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::{
    block::{self, Header},
    BlockHash,
};
use eyre::Context;
use risc0_zkvm::Receipt;

impl Database {
    /// Adds a new block to the database, later to be updated with a proof.
    pub async fn save_unproven_block(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: block::BlockHash,
        block_header: block::Header,
        block_height: u64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
                "INSERT INTO header_chain_proofs (block_hash, block_header, prev_block_hash, height) VALUES ($1, $2, $3, $4);",
            )
            .bind(BlockHashDB(block_hash)).bind(BlockHeaderDB(block_header)).bind(BlockHashDB(block_header.prev_blockhash)).bind(block_height as i64);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_latest_block_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u64>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM header_chain_proofs ORDER BY height DESC LIMIT 1;");

        let result: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result.map(|height| height.0 as u64))
    }

    /// Gets the newest block's info that it's previous block has proven before.
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
    pub async fn get_next_non_proven_block(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<(BlockHash, Header, u64, Receipt)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                    h1.block_header,
                    h1.height,
                    h2.proof
                FROM header_chain_proofs h1
                JOIN header_chain_proofs h2 ON h1.prev_block_hash = h2.block_hash
                WHERE h2.proof IS NOT NULL
                ORDER BY h1.height DESC
                LIMIT 1;",
        );

        let result: Option<(BlockHashDB, BlockHeaderDB, i64, Vec<u8>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        let result = match result {
            Some(result) => {
                let receipt: Receipt =
                    borsh::from_slice(&result.3).wrap_err(BridgeError::BorshError)?;
                let height = result.2.try_into().wrap_err("Can't convert i64 to u64")?;
                Some((result.0 .0, result.1 .0, height, receipt))
            }
            None => None,
        };

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
        tx: Option<DatabaseTransaction<'_, '_>>,
        count: u32,
    ) -> Result<Vec<(BlockHash, Header, u64, Receipt)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                    h1.block_header,
                    h1.height,
                    h2.proof
                FROM header_chain_proofs h1
                JOIN header_chain_proofs h2 ON h1.prev_block_hash = h2.block_hash
                WHERE h2.proof IS NOT NULL
                ORDER BY h1.height
                LIMIT $1;",
        )
        .bind(i32::try_from(count).wrap_err(BridgeError::IntConversionError)?);

        let result: Vec<(BlockHashDB, BlockHeaderDB, i64, Vec<u8>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        result
            .iter()
            .map(|result| {
                let receipt: Receipt =
                    borsh::from_slice(&result.3).wrap_err(BridgeError::BorshError)?;
                let height = result.2.try_into().wrap_err("Can't convert i64 to u64")?;
                Ok((result.0 .0, result.1 .0, height, receipt))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
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
            "SELECT block_hash, block_header, height FROM header_chain_proofs WHERE proof IS NOT NULL ORDER BY height DESC LIMIT 1;",
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

    /// Sets an existing block's (in database) proof by referring to it by it's
    /// hash.
    pub async fn set_block_proof(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        hash: block::BlockHash,
        proof: Receipt,
    ) -> Result<(), BridgeError> {
        let proof = borsh::to_vec(&proof).wrap_err(BridgeError::BorshError)?;

        let query = sqlx::query("UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2;")
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
        let query = sqlx::query_as("SELECT proof FROM header_chain_proofs WHERE block_hash = $1;")
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

        assert!(db.get_latest_block_height(None).await.unwrap().is_none());

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
        db.save_unproven_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            db.get_latest_block_height(None).await.unwrap().unwrap(),
            height
        );
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
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
        db.save_unproven_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        let (read_block_hash, read_block_header, _, _) =
            db.get_next_non_proven_block(None).await.unwrap().unwrap();
        assert_eq!(block_hash, read_block_hash);
        assert_eq!(block.header, read_block_header);
    }

    #[tokio::test]
    #[serial_test::serial]
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
        db.save_unproven_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        // Requesting proof for an existing block without a proof should
        // return `None`.
        let read_receipt = db.get_block_proof_by_hash(None, block_hash).await.unwrap();
        assert!(read_receipt.is_none());

        // Update it with a proof.
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
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
    #[serial_test::serial]
    pub async fn get_non_proven_block() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        assert!(db.get_next_non_proven_block(None).await.unwrap().is_none());
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
        db.save_unproven_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db.get_next_non_proven_block(None).await.unwrap().is_none());
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
        db.save_unproven_block(None, block_hash1, block.header, height1)
            .await
            .unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db.get_next_non_proven_block(None).await.unwrap().is_none());
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
        db.save_unproven_block(None, block_hash2, block.header, height2)
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return third block's details.
        let res = db.get_next_non_proven_block(None).await.unwrap().unwrap();
        assert_eq!(res.0, block_hash2);
        assert_eq!(res.2 as u64, height2);

        // Save fourth block without a proof.
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
        db.save_unproven_block(None, block_hash3, block.header, height3)
            .await
            .unwrap();

        // Set third block's proof.
        db.set_block_proof(None, block_hash2, receipt.clone())
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return fourth block's details.
        let res = db.get_next_non_proven_block(None).await.unwrap().unwrap();
        assert_eq!(res.0, block_hash3);
        assert_eq!(res.2 as u64, height3);
    }

    #[tokio::test]
    #[serial_test::serial]
    pub async fn get_non_proven_blocks() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        let batch_size = config.protocol_paramset().header_chain_proof_batch_size;

        assert!(db
            .get_next_n_non_proven_block(None, batch_size)
            .await
            .unwrap()
            .is_empty());
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
        db.save_unproven_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db
            .get_next_n_non_proven_block(None, batch_size)
            .await
            .unwrap()
            .is_empty());
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
        db.save_unproven_block(None, block_hash1, block.header, height)
            .await
            .unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db
            .get_next_n_non_proven_block(None, batch_size)
            .await
            .unwrap()
            .is_empty());
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
        for i in 0..batch_size {
            let block = block::Block {
                header: Header {
                    version: Version::TWO,
                    prev_blockhash: block_hash1,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0x1F,
                    bits: CompactTarget::default(),
                    nonce: 0x45 + 2 + i,
                },
                txdata: vec![],
            };
            let block_hash = block.block_hash();
            height += 1;
            db.save_unproven_block(None, block_hash, block.header, height)
                .await
                .unwrap();

            blocks.push((block_hash, height.try_into().unwrap()));
        }

        // This time, `get_non_proven_block` should return third block's details.
        let res = db
            .get_next_n_non_proven_block(None, batch_size)
            .await
            .unwrap();
        assert_eq!(res.len(), batch_size as usize);
        for i in 0..batch_size {
            tracing::error!("i: {i}");
            let i = i as usize;
            assert_eq!(res[i].2, blocks[i].1 as u64);
            assert_eq!(res[i].0, blocks[i].0);
        }
    }
}
