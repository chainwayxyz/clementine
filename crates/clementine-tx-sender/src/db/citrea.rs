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
    /// Group identifier shared across all rows belonging to the same RawTxData request.
    pub insertion_id: i64,
    /// Transaction kind as defined in `citrea::TransactionKind`.
    pub transaction_kind: TransactionKind,
    /// Raw body bytes.
    pub body: Vec<u8>,
    /// Optional commit outpoint once known.
    pub commit_outpoint: Option<OutPoint>,
    /// Optional link to a tx_sender_try_to_send_txs row once it exists.
    pub try_to_send_id: Option<i32>,
}

/// Raw row shape returned by SQLx for Citrea queue rows.
type CitreaRawTxRowDb = (
    i64,
    i64,
    i16,
    Option<Vec<u8>>,
    Option<OutPointDB>,
    Option<i32>,
);

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
            "INSERT INTO tx_sender_citrea_raw_tx_queue (transaction_kind, body, body_hash)
             VALUES ($1, $2, $3)
             RETURNING insertion_id",
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

        let insertion_id_query = sqlx::query_scalar::<_, i64>(
            "INSERT INTO tx_sender_citrea_raw_tx_queue (transaction_kind, body, body_hash)
             VALUES ($1, $2, $3)
             RETURNING insertion_id",
        )
        .bind(TransactionKind::Chunks.as_i16())
        .bind(first_chunk.as_slice())
        .bind(calculate_sha256(first_chunk).to_vec());

        let insertion_id = insertion_id_query.fetch_one(&mut **tx).await?;

        // Insert remaining chunks (1..N-1)
        for chunk in chunks.iter().skip(1) {
            let query = sqlx::query(
                "INSERT INTO tx_sender_citrea_raw_tx_queue (insertion_id, transaction_kind, body, body_hash)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(insertion_id)
            .bind(TransactionKind::Chunks.as_i16())
            .bind(chunk.as_slice())
            .bind(calculate_sha256(chunk).to_vec());

            query.execute(&mut **tx).await?;
        }

        // Insert aggregate placeholder row
        let aggregate_query = sqlx::query(
            "INSERT INTO tx_sender_citrea_raw_tx_queue (insertion_id, transaction_kind, body, body_hash)
             VALUES ($1, $2, NULL, NULL)",
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
        let query = sqlx::query_as::<
            _,
            (
                i64,
                i64,
                i16,
                Option<Vec<u8>>,
                Option<OutPointDB>,
                Option<i32>,
            ),
        >(
            "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id
             FROM tx_sender_citrea_raw_tx_queue
             WHERE transaction_kind != $1
               AND commit_outpoint IS NULL
               AND body IS NOT NULL
             ORDER BY created_at ASC",
        )
        .bind(TransactionKind::Aggregate.as_i16());

        let results: Vec<CitreaRawTxRowDb> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

        results
            .into_iter()
            .map(
                |(id, insertion_id, kind, body, commit_outpoint, try_to_send_id)| {
                    let transaction_kind = TransactionKind::from_u16(kind as u16);
                    let body = body.ok_or_eyre("Expected body to be present")?;
                    let commit_outpoint = commit_outpoint.map(|op| op.0);
                    Ok(CitreaRawTxRow {
                        id,
                        insertion_id,
                        transaction_kind,
                        body,
                        commit_outpoint,
                        try_to_send_id,
                    })
                },
            )
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    /// Returns non-aggregate citrea transactions with commit_outpoint but no try_to_send_id.
    /// Excludes aggregate transactions (transaction_kind = 1).
    pub async fn get_citrea_txs_with_commit_outpoint_no_try_to_send(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<CitreaRawTxRow>, BridgeError> {
        let query = sqlx::query_as::<_, CitreaRawTxRowDb>(
            "SELECT id, insertion_id, transaction_kind, body, commit_outpoint, try_to_send_id
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

        results
            .into_iter()
            .map(
                |(id, insertion_id, kind, body, commit_outpoint, try_to_send_id)| {
                    let transaction_kind = TransactionKind::from_u16(kind as u16);
                    let body = body.ok_or_eyre("Expected body to be present")?;
                    let commit_outpoint = commit_outpoint
                        .ok_or_eyre("Expected commit_outpoint to be present")?
                        .0;
                    Ok(CitreaRawTxRow {
                        id,
                        insertion_id,
                        transaction_kind,
                        body,
                        commit_outpoint: Some(commit_outpoint),
                        try_to_send_id,
                    })
                },
            )
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
}
