use super::{wrapper::BlockHashDB, Database, DatabaseTransaction};
use crate::{bitcoin_syncer::BitcoinSyncerEvent, errors::BridgeError, execute_query_with_tx};
use bitcoin::BlockHash;
use std::{ops::DerefMut, str::FromStr};

impl Database {
    pub async fn add_block_info(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: &BlockHash,
        prev_block_hash: &BlockHash,
        block_height: i64,
    ) -> Result<i32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO bitcoin_syncer (blockhash, prev_blockhash, height) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(BlockHashDB(*block_hash))
        .bind(BlockHashDB(*prev_block_hash))
        .bind(block_height);

        let id = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        Ok(id)
    }

    pub async fn get_max_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u64>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM bitcoin_syncer WHERE is_canonical = true ORDER BY height DESC LIMIT 1");
        let result: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(result.map(|(height,)| height as u64))
    }

    /// Gets the height from the block hash.
    pub async fn get_height_from_block_hash(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: BlockHash,
    ) -> Result<Option<u64>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT height FROM bitcoin_syncer WHERE blockhash = $1 AND is_canonical = true",
        )
        .bind(block_hash.to_string());

        let height: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(height.map(|(h,)| h as u64))
    }

    /// Gets the block hashes that have height bigger then the given height and deletes them.
    pub async fn set_non_canonical_block_hashes(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u64,
    ) -> Result<Vec<BlockHash>, BridgeError> {
        let query = sqlx::query_as(
            "WITH deleted AS (
                UPDATE bitcoin_syncer 
                SET is_canonical = false 
                WHERE height > $1 
                RETURNING blockhash
            ) SELECT blockhash FROM deleted",
        )
        .bind(height as i64);

        let block_hashes: Vec<(String,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        Ok(block_hashes
            .into_iter()
            .map(|(hash,)| BlockHash::from_str(&hash))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub async fn insert_tx(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: i32,
        txid: &bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        sqlx::query("INSERT INTO bitcoin_syncer_txs (block_id, txid) VALUES ($1, $2)")
            .bind(block_id)
            .bind(super::wrapper::TxidDB(*txid))
            .execute(tx.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn insert_spent_utxo(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: i32,
        spending_txid: &bitcoin::Txid,
        txid: &bitcoin::Txid,
        vout: i64,
    ) -> Result<(), BridgeError> {
        sqlx::query(
            "INSERT INTO bitcoin_syncer_spent_utxos (block_id, spending_txid, txid, vout) VALUES ($1, $2, $3, $4)",
        )
        .bind(block_id)
        .bind(super::wrapper::TxidDB(*spending_txid))
        .bind(super::wrapper::TxidDB(*txid))
        .bind(vout)
        .execute(tx.deref_mut())
        .await?;
        Ok(())
    }
    pub async fn add_event(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        event_type: BitcoinSyncerEvent,
    ) -> Result<(), BridgeError> {
        let query = match event_type {
            BitcoinSyncerEvent::NewBlock(block_hash) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (blockhash, event_type) VALUES ($1, 'new_block'::bitcoin_syncer_event_type)",
            )
            .bind(BlockHashDB(block_hash)),
            BitcoinSyncerEvent::ReorgedBlock(block_hash) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (blockhash, event_type) VALUES ($1, 'reorged_block'::bitcoin_syncer_event_type)",
            )
            .bind(BlockHashDB(block_hash)),
        };
        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn confirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<(), BridgeError> {
        // Update tx_sender_fee_payer_utxos
        sqlx::query(
            r#"
            UPDATE tx_sender_fee_payer_utxos utxos
            SET 
                is_confirmed = true,
                confirmed_blockhash = bs.blockhash
            FROM bitcoin_syncer_txs bstx
            JOIN bitcoin_syncer bs ON bstx.block_id = bs.id
            WHERE utxos.fee_payer_txid = bstx.txid
              AND bs.blockhash = $1
            "#,
        )
        .bind(BlockHashDB(*block_hash))
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_txs
        sqlx::query(
            r#"
            UPDATE tx_sender_txs txs
            SET 
                is_confirmed = true,
                confirmed_blockhash = bs.blockhash
            FROM bitcoin_syncer_txs bstx
            JOIN bitcoin_syncer bs ON bstx.block_id = bs.id
            WHERE txs.txid = bstx.txid
              AND bs.blockhash = $1
            "#,
        )
        .bind(BlockHashDB(*block_hash))
        .execute(tx.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn unconfirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<(), BridgeError> {
        // Unconfirm tx_sender_fee_payer_utxos
        sqlx::query(
            r#"
            UPDATE tx_sender_fee_payer_utxos utxos
            SET 
                is_confirmed = false,
                confirmed_blockhash = NULL
            FROM bitcoin_syncer_txs bstx
            JOIN bitcoin_syncer bs ON bstx.block_id = bs.id
            WHERE utxos.fee_payer_txid = bstx.txid
              AND bs.blockhash = $1
            "#,
        )
        .bind(BlockHashDB(*block_hash))
        .execute(tx.deref_mut())
        .await?;

        // Unconfirm tx_sender_txs
        sqlx::query(
            r#"
            UPDATE tx_sender_txs txs
            SET 
                is_confirmed = false,
                confirmed_blockhash = NULL
            FROM bitcoin_syncer_txs bstx
            JOIN bitcoin_syncer bs ON bstx.block_id = bs.id
            WHERE txs.txid = bstx.txid
              AND bs.blockhash = $1
            "#,
        )
        .bind(BlockHashDB(*block_hash))
        .execute(tx.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_event_and_update(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        consumer_handle: &str,
    ) -> Result<Option<BitcoinSyncerEvent>, BridgeError> {
        // Step 1: Insert the consumer_handle if it doesn't exist
        sqlx::query(
            r#"
            INSERT INTO bitcoin_syncer_event_handlers (consumer_handle, last_processed_event_id)
            VALUES ($1, 0)
            ON CONFLICT (consumer_handle) DO NOTHING
            "#,
        )
        .bind(consumer_handle)
        .execute(tx.deref_mut())
        .await?;

        // Step 2: Get the last processed event ID for this consumer
        let last_processed_event_id: i32 = sqlx::query_scalar(
            r#"
            SELECT last_processed_event_id
            FROM bitcoin_syncer_event_handlers
            WHERE consumer_handle = $1
            "#,
        )
        .bind(consumer_handle)
        .fetch_one(tx.deref_mut())
        .await?;

        // Step 3: Retrieve the next event that hasn't been processed yet
        let event = sqlx::query_as::<_, (i32, BlockHashDB, String)>(
            r#"
            SELECT id, blockhash, event_type::text
            FROM bitcoin_syncer_events
            WHERE id > $1
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(last_processed_event_id)
        .fetch_optional(tx.deref_mut())
        .await?;

        if event.is_none() {
            return Ok(None);
        }

        let event = event.expect("should exist since we checked is_none()");
        let event_type = match event.2.as_str() {
            "new_block" => BitcoinSyncerEvent::NewBlock(event.1 .0),
            "reorged_block" => BitcoinSyncerEvent::ReorgedBlock(event.1 .0),
            _ => return Err(BridgeError::Error("Invalid event type".to_string())),
        };
        let event_id = event.0;

        // Step 5: Update last_processed_event_id for this consumer
        sqlx::query(
            r#"
            UPDATE bitcoin_syncer_event_handlers
            SET last_processed_event_id = $1
            WHERE consumer_handle = $2
            "#,
        )
        .bind(event_id)
        .bind(consumer_handle)
        .execute(tx.deref_mut())
        .await?;

        Ok(Some(event_type))
    }
}
