//! Citrea-specific SQLx queries for tx-sender tables.

use super::wrapper::OutPointDB;
use super::{TxSenderDb, TxSenderDbTx};
use crate::txsender_execute_query_with_tx;
use bitcoin::OutPoint;
use clementine_errors::BridgeError;
use eyre::OptionExt;

use crate::citrea::{calculate_sha256, TransactionKind};

/// Represents a single Citrea raw transaction queue row.
#[derive(Debug, Clone)]
pub struct CitreaRawTxRow {
    /// Database row ID.
    pub id: i64,
    /// Group identifier shared across all rows belonging to the same CitreaTxRequest.
    pub insertion_id: i64,
    /// Transaction kind as defined in `citrea::TransactionKind`.
    pub transaction_kind: TransactionKind,
    /// Raw body bytes.
    pub body: Vec<u8>,
    /// Optional commit outpoint once known.
    pub commit_outpoint: Option<OutPoint>,
    /// Optional link to a tx_sender_try_to_send_txs row once it exists.
    pub try_to_send_id: Option<i32>,
    /// Whether this aggregate row is finalized and should not be reprocessed.
    pub aggregate_finalized: bool,
}

/// Raw row shape returned by SQLx for Citrea queue rows.
type CitreaRawTxRowDb = (
    i64,
    i64,
    i16,
    Option<Vec<u8>>,
    Option<OutPointDB>,
    Option<i32>,
    bool,
);

impl From<CitreaRawTxRowDb> for CitreaRawTxRow {
    fn from(row: CitreaRawTxRowDb) -> Self {
        let (id, insertion_id, kind, body, commit_outpoint, try_to_send_id, aggregate_finalized) =
            row;
        Self {
            id,
            insertion_id,
            transaction_kind: TransactionKind::from_u16(kind as u16),
            body: body.unwrap_or_default(),
            commit_outpoint: commit_outpoint.map(|op| op.0),
            try_to_send_id,
            aggregate_finalized,
        }
    }
}

impl TxSenderDb {
    /// Inserts a single non-chunked Citrea raw tx row.
    /// Returns the insertion_id assigned to this row.
    pub async fn insert_citrea_raw_tx_single(
        &self,
        tx: TxSenderDbTx<'_>,
        transaction_kind: TransactionKind,
        body: &[u8],
    ) -> Result<i64, BridgeError> {
        let body_hash = calculate_sha256(body).to_vec();
        let query = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO tx_sender_citrea_raw_tx_queue (transaction_kind, body, body_hash)
            VALUES ($1, $2, $3)
            RETURNING insertion_id
            "#,
        )
        .bind(transaction_kind.as_i16())
        .bind(body)
        .bind(body_hash);

        let insertion_id = query.fetch_one(&mut **tx).await?;
        Ok(insertion_id)
    }

    /// Sets the commit outpoint for a specific Citrea raw tx row.
    pub async fn set_citrea_commit_outpoint(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: i64,
        outpoint: OutPoint,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_citrea_raw_tx_queue SET commit_outpoint = $2 WHERE id = $1",
        )
        .bind(id)
        .bind(OutPointDB(outpoint));

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Inserts chunked Citrea raw tx data: N chunk rows + 1 aggregate row.
    /// All rows share the same insertion_id.
    /// Returns the insertion_id assigned to this group.
    pub async fn insert_citrea_raw_tx_chunks(
        &self,
        tx: TxSenderDbTx<'_>,
        chunks: &[Vec<u8>],
    ) -> Result<i64, BridgeError> {
        // First, get a new insertion_id by inserting the first chunk
        // This will fail if body is duplicate, which is what we want
        let first_chunk = chunks.first().ok_or_eyre("Chunks vector cannot be empty")?;

        // insert first chunk and generate the insertion_id, all others will be added with same insertion id
        let insertion_id = self
            .insert_citrea_raw_tx_single(tx, TransactionKind::Chunks, first_chunk)
            .await?;

        // Insert remaining chunks (1..N-1)
        for chunk in chunks.iter().skip(1) {
            let query = sqlx::query(
                r#"
                INSERT INTO tx_sender_citrea_raw_tx_queue (insertion_id, transaction_kind, body, body_hash)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(insertion_id)
            .bind(TransactionKind::Chunks.as_i16())
            .bind(chunk.as_slice())
            .bind(calculate_sha256(chunk).to_vec());

            query.execute(&mut **tx).await?;
        }

        // Insert aggregate placeholder row, do not add a duplicate
        let aggregate_query = sqlx::query(
            r#"
            INSERT INTO tx_sender_citrea_raw_tx_queue (insertion_id, transaction_kind, body, body_hash)
            SELECT $1, $2, NULL, NULL
            WHERE NOT EXISTS (
                SELECT 1 FROM tx_sender_citrea_raw_tx_queue 
                WHERE insertion_id = $1 AND transaction_kind = $2
            )
            "#,
        )
        .bind(insertion_id)
        .bind(TransactionKind::Aggregate.as_i16());

        aggregate_query.execute(&mut **tx).await?;

        Ok(insertion_id)
    }

    /// Returns non-aggregate citrea transactions with null commit_outpoint.
    /// Excludes aggregate transactions (transaction_kind = 1).
    pub async fn get_citrea_txs_with_null_commit_outpoint(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
                        "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id, aggregate_finalized
             FROM tx_sender_citrea_raw_tx_queue
             WHERE transaction_kind != $1
               AND commit_outpoint IS NULL
               AND body IS NOT NULL
             ORDER BY created_at ASC",
        )
        .bind(TransactionKind::Aggregate.as_i16());

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        Ok(results.into_iter().map(CitreaRawTxRow::from).collect())
    }

    /// Returns non-aggregate citrea transactions with commit_outpoint but no try_to_send_id.
    /// Excludes aggregate transactions (transaction_kind = 1).
    pub async fn get_citrea_txs_with_commit_outpoint_no_try_to_send(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
                        "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id, aggregate_finalized
             FROM tx_sender_citrea_raw_tx_queue
             WHERE transaction_kind != $1
               AND commit_outpoint IS NOT NULL
               AND try_to_send_id IS NULL
               AND body IS NOT NULL
             ORDER BY created_at ASC",
        )
        .bind(TransactionKind::Aggregate.as_i16());

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        Ok(results.into_iter().map(CitreaRawTxRow::from).collect())
    }

    /// Returns citrea transactions with commit_outpoint (regardless of try_to_send_id).
    pub async fn get_citrea_txs_with_commit_outpoint(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
            "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id, aggregate_finalized
             FROM tx_sender_citrea_raw_tx_queue
             WHERE commit_outpoint IS NOT NULL",
        );

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        Ok(results.into_iter().map(CitreaRawTxRow::from).collect())
    }

    /// Returns non-aggregate citrea transactions with commit_outpoint where
    /// try_to_send_id is NULL or the try_to_send tx has not been seen yet.
    pub async fn get_citrea_txs_with_unseen_try_to_send(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
                        "SELECT q.id, q.insertion_id, q.transaction_kind, q.body, q.commit_outpoint, q.try_to_send_id, q.aggregate_finalized
             FROM tx_sender_citrea_raw_tx_queue q
             LEFT JOIN tx_sender_try_to_send_txs t
               ON t.id = q.try_to_send_id
             WHERE q.commit_outpoint IS NOT NULL
               AND (q.try_to_send_id IS NULL OR t.seen_at_height IS NULL)
             ORDER BY q.id ASC",
        );

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        Ok(results.into_iter().map(CitreaRawTxRow::from).collect())
    }

    /// Clears commit_outpoint and try_to_send_id for all citrea rows in an insertion group.
    pub async fn clear_citrea_commit_and_try_to_send_by_insertion_id(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        insertion_id: i64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_citrea_raw_tx_queue
             SET commit_outpoint = NULL, try_to_send_id = NULL
             WHERE insertion_id = $1",
        )
        .bind(insertion_id);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Lists distinct try_to_send_ids for an insertion group.
    pub async fn list_citrea_try_to_send_ids_by_insertion_id(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        insertion_id: i64,
    ) -> Result<Vec<u32>, BridgeError> {
        let query = sqlx::query_scalar::<_, i32>(
            "SELECT DISTINCT try_to_send_id
             FROM tx_sender_citrea_raw_tx_queue
             WHERE insertion_id = $1
               AND try_to_send_id IS NOT NULL",
        )
        .bind(insertion_id);

        let results: Vec<i32> = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        results
            .into_iter()
            .map(|id| u32::try_from(id).map_err(|_| BridgeError::IntConversionError))
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    /// Sets the try_to_send_id for a specific Citrea raw tx row.
    pub async fn set_citrea_try_to_send_id(
        &self,
        tx: TxSenderDbTx<'_>,
        id: i64,
        try_to_send_id: i32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_citrea_raw_tx_queue SET try_to_send_id = $2 WHERE id = $1",
        )
        .bind(id)
        .bind(try_to_send_id);

        query.execute(&mut **tx).await?;
        Ok(())
    }

    /// Returns aggregate placeholder rows that are not finalized.
    pub async fn get_citrea_aggregate_rows_pending(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
            "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id, aggregate_finalized
             FROM tx_sender_citrea_raw_tx_queue
             WHERE transaction_kind = $1
               AND aggregate_finalized = FALSE
             ORDER BY created_at ASC",
        )
        .bind(TransactionKind::Aggregate.as_i16());

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        Ok(results.into_iter().map(CitreaRawTxRow::from).collect())
    }

    /// Returns chunk rows for a given insertion_id, ordered by row id.
    pub async fn get_citrea_chunk_rows_by_insertion_id(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        insertion_id: i64,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
            "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id, aggregate_finalized
             FROM tx_sender_citrea_raw_tx_queue
             WHERE insertion_id = $1
               AND transaction_kind = $2
             ORDER BY id ASC",
        )
        .bind(insertion_id)
        .bind(TransactionKind::Chunks.as_i16());

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        Ok(results.into_iter().map(CitreaRawTxRow::from).collect())
    }

    /// Updates the body and hash for a Citrea row, resetting commit/try_to_send state.
    pub async fn update_citrea_body_and_reset(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: i64,
        body: &[u8],
    ) -> Result<(), BridgeError> {
        let body_hash = calculate_sha256(body).to_vec();
        let query = sqlx::query(
            "UPDATE tx_sender_citrea_raw_tx_queue
             SET body = $2,
                 body_hash = $3,
                 commit_outpoint = NULL,
                 try_to_send_id = NULL,
                 aggregate_finalized = FALSE
             WHERE id = $1",
        )
        .bind(id)
        .bind(body)
        .bind(body_hash);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Marks an aggregate row as finalized.
    pub async fn set_citrea_aggregate_finalized(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: i64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_citrea_raw_tx_queue
             SET aggregate_finalized = TRUE
             WHERE id = $1",
        )
        .bind(id);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }
}
