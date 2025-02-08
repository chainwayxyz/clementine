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
    block::{self, Header, Version},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use risc0_zkvm::Receipt;

impl Database {
    /// Adds a new block to the database, later to be updated by a proof.
    pub async fn set_new_block(
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

    /// Returns a block's hash and header, referring to it by it's height.
    pub async fn get_block_info_by_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u64,
    ) -> Result<(block::BlockHash, block::Header), BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header FROM header_chain_proofs WHERE height = $1;",
        )
        .bind(height as i64);

        let result: (Option<BlockHashDB>, Option<BlockHeaderDB>) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        match result {
            (Some(hash), Some(header)) => Ok((hash.0, header.0)),
            _ => Ok((
                // TODO: Do we need to return all zeroed values or an error?
                BlockHash::all_zeros(),
                Header {
                    version: Version::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::default(),
                    nonce: 0,
                },
            )),
        }
    }

    /// Returns a block's header, referring to it by it's height and hash.
    pub async fn get_block_header(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_height: u64,
        block_hash: BlockHash,
    ) -> Result<Option<block::Header>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_header FROM header_chain_proofs WHERE height = $1 AND block_hash = $2;",
        )
        .bind(block_height as i64)
        .bind(BlockHashDB(block_hash));

        let result: (Option<BlockHeaderDB>,) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        match result {
            (Some(block_header),) => Ok(Some(block_header.0)),
            (None,) => Ok(None),
        }
    }

    /// Gets the block info of the latest block that has been saved to the
    /// database.
    pub async fn get_latest_block_info(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<(u64, BlockHash), BridgeError> {
        let query = sqlx::query_as(
            "SELECT height, block_hash FROM header_chain_proofs ORDER BY height DESC;",
        );

        let result: (Option<i32>, Option<BlockHashDB>) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        match result {
            (Some(height), Some(hash)) => Ok((height as u64, hash.0)),
            _ => Ok((0, BlockHash::all_zeros())),
        }
    }

    /// Sets an existing block's (in database) proof by referring to it by it's
    /// hash.
    pub async fn set_block_proof(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        hash: block::BlockHash,
        proof: Receipt,
    ) -> Result<(), BridgeError> {
        let proof = borsh::to_vec(&proof).map_err(BridgeError::BorshError)?;

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

        let receipt: Receipt = borsh::from_slice(&receipt).map_err(BridgeError::BorshError)?;

        Ok(Some(receipt))
    }

    /// Gets the newest block's info that it's previous block has proven before.
    /// This block will be the candidate block for the prover.
    pub async fn get_non_proven_block(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<(BlockHash, Header, i32, Receipt), BridgeError> {
        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                    h1.block_header,
                    h1.height,
                    h2.proof
                FROM header_chain_proofs h1
                JOIN header_chain_proofs h2 ON h1.prev_block_hash = h2.block_hash
                WHERE h2.proof IS NOT NULL
                ORDER BY h1.height
                LIMIT 1;",
        );

        let result: (BlockHashDB, BlockHeaderDB, i32, Vec<u8>) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        let receipt: Receipt = borsh::from_slice(&result.3).map_err(BridgeError::BorshError)?;

        Ok((result.0 .0, result.1 .0, result.2, receipt))
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use crate::{create_test_config_with_thread_name, database::Database};
    use bitcoin::block::{self, Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use borsh::BorshDeserialize;
    use risc0_zkvm::Receipt;

    #[tokio::test]
    async fn save_get_new_block() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

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
        let height = 0x45;

        db.set_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        let (read_block_hash, read_block_header) =
            db.get_block_info_by_height(None, height).await.unwrap();
        assert_eq!(block_hash, read_block_hash);
        assert_eq!(block.header, read_block_header);
    }

    #[tokio::test]
    async fn get_block_header() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

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
        let block_header = block.header;
        let block_height = 0x45;

        assert!(db
            .get_block_header(None, block_height, block_hash)
            .await
            .is_err());

        db.set_new_block(None, block_hash, block_header, block_height)
            .await
            .unwrap();
        assert_eq!(
            db.get_block_header(None, block_height, block_hash)
                .await
                .unwrap()
                .unwrap(),
            block_header
        );
    }

    #[tokio::test]
    pub async fn get_latest_chain_proof_height() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let mut block = block::Block {
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

        assert!(db.get_latest_block_info(None).await.is_err());

        // Adding a new block should return a height.
        let height = 0x1F;
        let hash = block.block_hash();
        db.set_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );

        // Adding a new block with smaller height should not effect what's
        // getting returned.
        let smaller_height = height - 1;
        block.header.time = 1; // To avoid same block hash.
        db.set_new_block(None, block.block_hash(), block.header, smaller_height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );

        // Adding another block with higher height should return a different
        // height.
        let height = 0x45;
        block.header.time = 2; // To avoid same block hash.
        let hash = block.block_hash();
        db.set_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );
    }

    #[tokio::test]
    pub async fn save_get_block_proof() {
        let config = create_test_config_with_thread_name!(None);
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
        db.set_new_block(None, block_hash, block.header, height)
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
    pub async fn get_non_proven_block() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        assert!(db.get_non_proven_block(None).await.is_err());

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
        db.set_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

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
        db.set_new_block(None, block_hash1, block.header, height1)
            .await
            .unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.set_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

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
        db.set_new_block(None, block_hash2, block.header, height2)
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return second block's details.
        let res = db.get_non_proven_block(None).await.unwrap();
        assert_eq!(res.0, block_hash2);
        assert_eq!(res.2 as u64, height2);
    }
}
