//! Chain proof related database operations.

use super::{
    wrapper::{BlockHashDB, BlockHeaderDB},
    Database,
};
use crate::errors::BridgeError;
use bitcoin::{
    block::{self, Header, Version},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use risc0_zkvm::Receipt;
use sqlx::Postgres;

impl Database {
    /// Saves a new block to the database, later to be updated by a proof.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_new_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        block_hash: block::BlockHash,
        block_header: block::Header,
        block_height: u64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO header_chain_proofs (block_hash, block_header, height) VALUES ($1, $2, $3);",
        )
        .bind(BlockHashDB(block_hash)).bind(BlockHeaderDB(block_header)).bind(block_height as i64);

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Sets a block's proof by referring to it by it's hash.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_block_proof(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
        proof: Receipt,
    ) -> Result<(), BridgeError> {
        let proof = borsh::to_vec(&proof)?;

        let query = sqlx::query("UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2;")
            .bind(proof)
            .bind(BlockHashDB(hash));

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Sets a block's proof by referring to it by it's hash.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_proof_by_hash(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
    ) -> Result<Option<Receipt>, BridgeError> {
        let query = sqlx::query_as("SELECT proof FROM header_chain_proofs WHERE block_hash = $1;")
            .bind(BlockHashDB(hash));

        let receipt: (Option<Vec<u8>>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;
        let receipt = match receipt.0 {
            Some(r) => r,
            None => return Ok(None),
        };

        let receipt: Receipt = borsh::from_slice(&receipt)?;

        Ok(Some(receipt))
    }

    /// Returns a blocks proof, by it's height.
    ///
    /// TODO: Add proof to return values.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_proof_info_by_height(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        height: u64,
    ) -> Result<(block::BlockHash, block::Header), BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header FROM header_chain_proofs WHERE height = $1;",
        )
        .bind(height as i64);

        let result: (Option<BlockHashDB>, Option<BlockHeaderDB>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(hash), Some(header)) => Ok((hash.0, header.0)),
            _ => Ok((
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_latest_block_info(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<(u64, BlockHash), BridgeError> {
        let query = sqlx::query_as(
            "SELECT height, block_hash FROM header_chain_proofs ORDER BY height DESC;",
        );

        let result: (Option<i32>, Option<BlockHashDB>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(height), Some(hash)) => Ok((height as u64, hash.0)),
            _ => Ok((0, BlockHash::all_zeros())),
        }
    }

    /// TODO: Return Option::None in case of last element is proven but it's
    /// ancestor is not.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_non_proven_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<(BlockHash, Header, i32, Receipt), BridgeError> {
        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                h1.block_header,
                h1.height,
                h2.proof
            FROM header_chain_proofs h1
            JOIN header_chain_proofs h2 ON h1.height = h2.height + 1
            WHERE h2.proof IS NOT NULL
            ORDER BY h1.height
            LIMIT 1;",
        );

        let result: (BlockHashDB, BlockHeaderDB, i32, Vec<u8>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        let receipt: Receipt = borsh::from_slice(&result.3)?;

        Ok((result.0 .0, result.1 .0, result.2, receipt))
    }
}

#[cfg(test)]
mod tests {
    use crate::{database::Database, mock::database::create_test_config_with_thread_name};
    use bitcoin::{
        block::{self, Header, Version},
        hashes::Hash,
        BlockHash, CompactTarget, TxMerkleNode,
    };
    use borsh::BorshDeserialize;
    use risc0_zkvm::Receipt;

    #[tokio::test]
    pub async fn save_get_new_block() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
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

        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        let (read_block_hash, read_block_header) = db
            .get_block_proof_info_by_height(None, height)
            .await
            .unwrap();
        assert_eq!(block_hash, read_block_hash);
        assert_eq!(block.header, read_block_header);
    }

    #[tokio::test]
    pub async fn get_latest_chain_proof_height() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
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
        db.save_new_block(None, hash, block.header, height)
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
        db.save_new_block(None, block.block_hash(), block.header, smaller_height)
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
        db.save_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );
    }

    #[tokio::test]
    pub async fn save_get_block_proof() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
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
        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        // Requesting proof for an existing block without a proof should
        // return `None`.
        let read_receipt = db.get_block_proof_by_hash(None, block_hash).await.unwrap();
        assert!(read_receipt.is_none());

        // Update it with a proof.
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.save_block_proof(None, block_hash, receipt.clone())
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
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        assert!(db.get_non_proven_block(None).await.is_err());

        let base_height = 0x45;

        // Save dummy block without a proof.
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
        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

        // Save dummy block with a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 1,
            },
            txdata: vec![],
        };
        let block_hash1 = block.block_hash();
        let height1 = base_height + 1;
        db.save_new_block(None, block_hash1, block.header, height1)
            .await
            .unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.save_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

        // Save dummy block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 3,
            },
            txdata: vec![],
        };
        let block_hash2 = block.block_hash();
        let height2 = base_height + 2;
        db.save_new_block(None, block_hash2, block.header, height2)
            .await
            .unwrap();

        let res = db.get_non_proven_block(None).await.unwrap();
        assert_eq!(res.0, block_hash2);
        assert_eq!(res.2 as u64, height2);
    }
}
