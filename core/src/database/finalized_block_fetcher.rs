use super::{Database, DatabaseTransaction};
use crate::execute_query_with_tx;
use bitcoin::BlockHash;
use clementine_errors::BridgeError;
use eyre::Context as _;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedBlockProgress {
    pub last_processed_height: u32,
    pub last_processed_block_hash: Option<BlockHash>,
}

impl Database {
    pub async fn get_finalized_block_progress(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        consumer_handle: &str,
    ) -> Result<Option<FinalizedBlockProgress>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT last_processed_height, last_processed_block_hash
             FROM finalized_block_fetcher_progress
             WHERE consumer_handle = $1",
        )
        .bind(consumer_handle);

        let result: Option<(i32, Option<String>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        let Some((height, block_hash)) = result else {
            return Ok(None);
        };

        let last_processed_height =
            u32::try_from(height).wrap_err(BridgeError::IntConversionError)?;
        let last_processed_block_hash = block_hash
            .as_deref()
            .map(BlockHash::from_str)
            .transpose()
            .wrap_err("Invalid finalized block hash stored in database")?;

        Ok(Some(FinalizedBlockProgress {
            last_processed_height,
            last_processed_block_hash,
        }))
    }

    pub async fn upsert_finalized_block_progress(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        consumer_handle: &str,
        last_processed_height: u32,
        last_processed_block_hash: BlockHash,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO finalized_block_fetcher_progress (
                consumer_handle,
                last_processed_height,
                last_processed_block_hash,
                updated_at
            ) VALUES ($1, $2, $3, NOW())
            ON CONFLICT (consumer_handle)
            DO UPDATE SET
                last_processed_height = EXCLUDED.last_processed_height,
                last_processed_block_hash = EXCLUDED.last_processed_block_hash,
                updated_at = NOW()",
        )
        .bind(consumer_handle)
        .bind(i32::try_from(last_processed_height).wrap_err(BridgeError::IntConversionError)?)
        .bind(last_processed_block_hash.to_string());

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }
}
