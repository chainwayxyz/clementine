use super::{Database, DatabaseTransaction};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::BlockHash;
use std::str::FromStr;

// pub async fn set_tx_sender_chain_head(
//     &self,
//     tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
//     block_hash: BlockHash,
//     height: u64,
// ) -> Result<(BlockHash, u64), BridgeError> {
//     sqlx::query("DELETE FROM tx_sender_block_info")
//         .execute(tx.deref_mut())
//         .await?;
//     sqlx::query("INSERT INTO tx_sender_block_info (block_hash, height) VALUES ($1, $2)")
//         .bind(block_hash.to_string())
//         .bind(height as i64)
//         .execute(tx.deref_mut())
//         .await?;
//     Ok((block_hash, height))
// }

// pub async fn get_tx_sender_chain_head(&self) -> Result<Option<(BlockHash, u64)>, BridgeError> {
//     let mut tx = self.begin_transaction().await?;
//     let ret: Option<(String, i64)> =
//         sqlx::query_as("SELECT block_hash, height FROM tx_sender_block_info LIMIT 1")
//             .fetch_optional(tx.deref_mut())
//             .await?;
//     if let Some((block_hash, height)) = ret {
//         let block_hash = BlockHash::from_str(&block_hash)?;
//         let height = height as u64;
//         Ok(Some((block_hash, height)))
//     } else {
//         Ok(None)
//     }
// }

impl Database {
    pub async fn set_chain_head(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: BlockHash,
        prev_block_hash: BlockHash,
        height: u64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_block_info (block_hash, prev_block_hash, height) VALUES ($1, $2, $3)",
        )
        .bind(block_hash.to_string())
        .bind(prev_block_hash.to_string())
        .bind(height as i64);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the height from the block hash.
    pub async fn get_height_from_block_hash(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: BlockHash,
    ) -> Result<Option<u64>, BridgeError> {
        let query = sqlx::query_as("SELECT height FROM tx_sender_block_info WHERE block_hash = $1")
            .bind(block_hash.to_string());

        let height: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(height.map(|(h,)| h as u64))
    }

    /// Gets the block hashes that have height bigger then the given height and deletes them.
    pub async fn delete_chain_head_from_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u64,
    ) -> Result<Vec<BlockHash>, BridgeError> {
        let query = sqlx::query_as(
            "WITH deleted AS (
                DELETE FROM tx_sender_block_info 
                WHERE height > $1 
                RETURNING block_hash
            ) SELECT block_hash FROM deleted",
        )
        .bind(height as i64);

        let block_hashes: Vec<(String,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        Ok(block_hashes
            .into_iter()
            .map(|(hash,)| BlockHash::from_str(&hash))
            .collect::<Result<Vec<_>, _>>()?)
    }
}
