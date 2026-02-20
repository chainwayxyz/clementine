//! # Transaction Sender Client
//!
//! This module is provides a client which is responsible for inserting
//! transactions into the sending queue.

use crate::ActivatedWithTxid;
use bitcoin::Transaction;
use clementine_errors::BridgeError;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::eyre;
use std::collections::BTreeMap;

#[cfg(feature = "citrea")]
use crate::citrea::CitreaTxRequest;
#[cfg(feature = "citrea")]
use crate::citrea::TransactionKind;

#[derive(Debug, Clone)]
pub struct TxSenderClient {
    pub db: crate::TxSenderDb,
}

impl TxSenderClient {
    pub fn new(db: crate::TxSenderDb) -> Self {
        Self { db }
    }

    /// Saves a transaction to the database queue for sending/fee bumping.
    ///
    /// This function determines the initial parameters for a transaction send attempt,
    /// including its [`FeePayingType`], associated metadata, and any txid-based
    /// activation prerequisites. It then persists this information in the database
    /// via [`Database::save_tx`] and related functions. The actual sending logic
    /// (CPFP/RBF) is handled later by the transaction sender's task loop.
    ///
    /// # Activation Conditions
    ///
    /// Activation is modeled purely in terms of txids.
    ///
    /// 1. Explicit activations are provided via the `activate_txids` argument.
    /// 2. Implicit activations are derived from the inputs of `signed_tx`:
    ///    for each input, the previous-output txid is treated as an activation
    ///    prerequisite, with an optional relative timelock taken from the input's
    ///    sequence (if it encodes a relative block height).
    ///
    /// For each txid, the maximum relative block height across both explicit
    /// and implicit activations is stored.
    ///
    /// # Arguments
    /// * `dbtx` - An active database transaction.
    /// * `tx_metadata` - Optional metadata about the transaction's purpose.
    /// * `signed_tx` - The transaction to be potentially sent.
    /// * `fee_paying_type` - Whether to use CPFP or RBF for fee management.
    /// * `rbf_signing_info` - Optional RBF signing info used when fee bumping via RBF if the signatures provided already is not a SighashSingle signature.
    /// * `activate_txids` - Additional txid activation prerequisites for this tx,
    ///   potentially with a relative timelock.
    ///
    /// # Returns
    ///
    /// - [`u32`]: The database ID (`try_to_send_id`) assigned to this send attempt.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE), skip_all, fields(?tx_metadata))]
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_try_to_send(
        &self,
        dbtx: &mut crate::TxSenderTransaction,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        rbf_signing_info: Option<RbfSigningInfo>,
        activate_txids: &[ActivatedWithTxid],
    ) -> Result<u32, BridgeError> {
        let txid = signed_tx.compute_txid();

        // do not add duplicate transactions to the txsender
        let tx_exists = self
            .db
            .check_if_tx_exists_on_txsender(Some(dbtx), txid)
            .await?;
        if let Some(try_to_send_id) = tx_exists {
            return Ok(try_to_send_id);
        }

        tracing::info!(
            "Added tx {} with txid {} to the queue",
            tx_metadata
                .as_ref()
                .map(|data| format!("{:?}", data.tx_type))
                .unwrap_or("N/A".to_string()),
            txid
        );

        let try_to_send_id = self
            .db
            .save_tx(
                dbtx,
                tx_metadata,
                signed_tx,
                fee_paying_type,
                txid,
                rbf_signing_info,
            )
            .await?;

        // only log the raw tx in tests so that logs do not contain sensitive information
        #[cfg(test)]
        tracing::debug!(target: "ci", "Saved tx to database with try_to_send_id: {try_to_send_id}, metadata: {tx_metadata:?}, raw tx: {}", hex::encode(bitcoin::consensus::serialize(signed_tx)));

        let mut max_timelock_of_activated_txids = BTreeMap::new();

        for activated_txid in activate_txids {
            let timelock = max_timelock_of_activated_txids
                .entry(activated_txid.txid)
                .or_insert(activated_txid.relative_block_height);
            if *timelock < activated_txid.relative_block_height {
                *timelock = activated_txid.relative_block_height;
            }
        }

        for input in signed_tx.input.iter() {
            let relative_block_height = if input.sequence.is_relative_lock_time() {
                let relative_locktime = input
                    .sequence
                    .to_relative_lock_time()
                    .expect("Invalid relative locktime");
                match relative_locktime {
                    bitcoin::relative::LockTime::Blocks(height) => height.value() as u32,
                    _ => {
                        return Err(BridgeError::Eyre(eyre!("Invalid relative locktime")));
                    }
                }
            } else {
                0
            };
            let timelock = max_timelock_of_activated_txids
                .entry(input.previous_output.txid)
                .or_insert(relative_block_height);
            if *timelock < relative_block_height {
                *timelock = relative_block_height;
            }
        }

        for (txid, timelock) in max_timelock_of_activated_txids {
            self.db
                .save_activated_txid(
                    dbtx,
                    try_to_send_id,
                    &ActivatedWithTxid {
                        txid,
                        relative_block_height: timelock,
                    },
                )
                .await?;
        }

        Ok(try_to_send_id)
    }

    #[cfg(feature = "citrea")]
    pub async fn send_citrea_tx(&self, request: CitreaTxRequest) -> Result<i64, eyre::Report> {
        use crate::citrea::data_serialization::DataOnDa;

        const MAX_CHUNK_SIZE: u32 = 390_000;

        let mut dbtx = self.db.begin_transaction().await?;

        let insertion_id = match request {
            CitreaTxRequest::BatchProof { bytes, chunk_size } => {
                let mut chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
                if chunk_size == 0 {
                    chunk_size = MAX_CHUNK_SIZE;
                }
                if chunk_size > MAX_CHUNK_SIZE {
                    chunk_size = MAX_CHUNK_SIZE;
                }
                let chunk_size = chunk_size as usize;

                if bytes.len() <= chunk_size {
                    let data = DataOnDa::Complete(bytes);
                    let blob = borsh::to_vec(&data).expect("zk::Proof serialize must not fail");
                    self.db
                        .insert_citrea_raw_tx_single(&mut dbtx, TransactionKind::Complete, &blob)
                        .await?
                } else {
                    let chunks: Vec<Vec<u8>> = bytes
                        .chunks(chunk_size)
                        .map(|chunk| {
                            borsh::to_vec(&DataOnDa::Chunk(chunk.to_vec()))
                                .expect("zk::Proof serialize must not fail")
                        })
                        .collect();
                    self.db
                        .insert_citrea_raw_tx_chunks(&mut dbtx, &chunks)
                        .await?
                }
            }
            CitreaTxRequest::BatchProofMethodId(body) => {
                if body.len() as u32 > MAX_CHUNK_SIZE {
                    return Err(eyre!(
                        "Citrea BatchProofMethodId DA payload body too large; max {} bytes",
                        MAX_CHUNK_SIZE,
                    ));
                }
                self.db
                    .insert_citrea_raw_tx_single(
                        &mut dbtx,
                        TransactionKind::BatchProofMethodId,
                        &body,
                    )
                    .await?
            }
            CitreaTxRequest::SequencerCommitment(body) => {
                if body.len() as u32 > MAX_CHUNK_SIZE {
                    return Err(eyre!(
                        "Citrea SequencerCommitment DA payload body too large; max {} bytes",
                        MAX_CHUNK_SIZE,
                    ));
                }
                self.db
                    .insert_citrea_raw_tx_single(
                        &mut dbtx,
                        TransactionKind::SequencerCommitment,
                        &body,
                    )
                    .await?
            }
        };

        self.db.commit_transaction(dbtx).await?;
        Ok(insertion_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    #[cfg(feature = "citrea")]
    #[tokio::test]
    async fn test_send_citrea_tx_batch_proof() {
        use crate::citrea::data_serialization::DataOnDa;
        use crate::citrea::CitreaTxRequest;
        use crate::test_utils::create_test_environment;

        let db = create_test_environment(true, false).await.1.unwrap();
        let client = TxSenderClient::new(db.clone());

        let body = vec![1, 2, 3, 4, 5];
        let insertion_id = client
            .send_citrea_tx(CitreaTxRequest::BatchProof {
                bytes: body.clone(),
                chunk_size: None,
            })
            .await
            .expect("Should insert successfully");

        let serialized_body =
            borsh::to_vec(&DataOnDa::Complete(body)).expect("Serialization should not fail");

        // Verify row was inserted
        let row = sqlx::query(
            "SELECT insertion_id, transaction_kind, body FROM tx_sender_citrea_raw_tx_queue WHERE body = $1",
        )
        .bind(&serialized_body)
        .fetch_one(db.pool())
        .await
        .expect("Should find inserted row");

        assert_eq!(row.get::<i16, _>("transaction_kind"), 0); // Complete
        assert_eq!(row.get::<Vec<u8>, _>("body"), serialized_body);
        assert_eq!(row.get::<i64, _>("insertion_id"), insertion_id);
    }

    #[cfg(feature = "citrea")]
    #[tokio::test]
    async fn test_send_citrea_tx_chunks() {
        use crate::citrea::data_serialization::DataOnDa;
        use crate::citrea::CitreaTxRequest;
        use crate::test_utils::create_test_environment;

        let db = create_test_environment(true, false).await.1.unwrap();
        let client = TxSenderClient::new(db.clone());

        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let chunks: Vec<Vec<u8>> = bytes.chunks(3).map(|chunk| chunk.to_vec()).collect();
        let insertion_id = client
            .send_citrea_tx(CitreaTxRequest::BatchProof {
                bytes,
                chunk_size: Some(3),
            })
            .await
            .expect("Should insert successfully");

        // Verify all chunk rows + aggregate row were inserted with same insertion_id
        let rows = sqlx::query(
            "SELECT insertion_id, transaction_kind, body FROM tx_sender_citrea_raw_tx_queue ORDER BY id ASC",
        )
        .fetch_all(db.pool())
        .await
        .expect("Should find inserted rows");

        assert_eq!(rows.len(), 4); // 3 chunks + 1 aggregate

        let db_insertion_id = rows[0].get::<i64, _>("insertion_id");
        assert_eq!(db_insertion_id, insertion_id);
        for (idx, row) in rows.iter().enumerate() {
            assert_eq!(row.get::<i64, _>("insertion_id"), insertion_id);
            if idx < 3 {
                // Chunk rows
                assert_eq!(row.get::<i16, _>("transaction_kind"), 2); // Chunks
                assert_eq!(
                    row.get::<Option<Vec<u8>>, _>("body"),
                    Some(
                        borsh::to_vec(&DataOnDa::Chunk(chunks[idx].clone()))
                            .expect("Serialization should not fail")
                    )
                );
            } else {
                // Aggregate row
                assert_eq!(row.get::<i16, _>("transaction_kind"), 1); // Aggregate
                assert_eq!(row.get::<Option<Vec<u8>>, _>("body"), None);
            }
        }
    }

    #[cfg(feature = "citrea")]
    #[tokio::test]
    async fn test_send_citrea_tx_duplicate_body() {
        use crate::citrea::CitreaTxRequest;
        use crate::test_utils::create_test_environment;

        let db = create_test_environment(true, false).await.1.unwrap();
        let client = TxSenderClient::new(db.clone());

        let body = vec![10, 20, 30];
        let first_insertion_id = client
            .send_citrea_tx(CitreaTxRequest::BatchProofMethodId(body.clone()))
            .await
            .expect("First insert should succeed");

        // Try to insert duplicate body - should return existing insertion_id
        let second_insertion_id = client
            .send_citrea_tx(CitreaTxRequest::BatchProofMethodId(body))
            .await
            .expect("Second insert should return existing insertion_id");

        assert_eq!(first_insertion_id, second_insertion_id);

        // Verify only one row exists
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tx_sender_citrea_raw_tx_queue WHERE body = $1",
        )
        .bind(vec![10u8, 20, 30])
        .fetch_one(db.pool())
        .await
        .expect("Should count rows");

        assert_eq!(count, 1, "Should have exactly one row with this body");
    }

    #[cfg(feature = "citrea")]
    #[tokio::test]
    #[ignore = "Think about duplicate body possibility first"]
    async fn test_send_citrea_tx_transaction_rollback() {
        use crate::citrea::CitreaTxRequest;
        use crate::test_utils::create_test_environment;

        let db = create_test_environment(true, false).await.1.unwrap();
        let client = TxSenderClient::new(db.clone());

        let body1 = vec![100, 200];
        // Insert first body
        client
            .send_citrea_tx(CitreaTxRequest::SequencerCommitment(body1))
            .await
            .expect("First insert should succeed");

        // Try to insert chunks where one chunk body duplicates body1
        // This should cause transaction rollback, so no rows should be inserted
        let bytes = vec![1, 2, 100, 200, 4, 5, 6];
        let result = client
            .send_citrea_tx(CitreaTxRequest::BatchProof {
                bytes,
                chunk_size: Some(2),
            })
            .await;

        assert!(result.is_err(), "Should fail due to duplicate body");

        // Verify no partial insert happened - count should be 1 (only the first insert)
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tx_sender_citrea_raw_tx_queue")
            .fetch_one(db.pool())
            .await
            .expect("Should count rows");

        assert_eq!(
            count, 1,
            "Should have only the first row, no partial chunk inserts"
        );
    }
}
