//! Chain proof related database operations.

use bitcoin::block;
use sqlx::Postgres;

use crate::{
    database::wrapper::{BlockHashDB, BlockHeaderDB},
    errors::BridgeError,
};

use super::Database;

impl Database {
    /// Saves a new block to the database, later to be updated by a proof.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_new_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
        header: block::Header,
        height: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO header_chain_proofs (block_hash, block_header, height) VALUES ($1, $2, $3);",
        )
        .bind(BlockHashDB(hash)).bind(BlockHeaderDB(header)).bind(height as i64);

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Sets a block's proof by referring it to by it's hash.
    ///
    /// TODO: Change proof type.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_block_proof(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
        proof: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2;")
            .bind(proof as i64)
            .bind(BlockHashDB(hash));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Returns a blocks proof, by it's height.
    ///
    /// TODO: Change proof type.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_proof_by_height(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        height: u32,
    ) -> Result<(), BridgeError> {
        // let query = sqlx::query(
        //     "UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2;",
        // )
        // .bind(proof as i64).bind(BlockHashDB(hash));

        // match tx {
        //     Some(tx) => query.execute(&mut **tx).await?,
        //     None => query.execute(&self.connection).await?,
        // };

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_latest_chain_proof_height(&self) -> Result<u32, BridgeError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        block::{self, Header, Version},
        hashes::Hash,
        BlockHash, CompactTarget, TxMerkleNode,
    };

    use crate::{database::Database, mock::database::create_test_config_with_thread_name};

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
    }
}
