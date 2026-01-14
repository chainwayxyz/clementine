//! # Transaction Sender Client
//!
//! This module is provides a client which is responsible for inserting
//! transactions into the sending queue.

use crate::{ActivatedWithOutpoint, ActivatedWithTxid};
use bitcoin::{OutPoint, Transaction, Txid};
use clementine_errors::BridgeError;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::eyre;
use std::collections::BTreeMap;

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
    /// including its [`FeePayingType`], associated metadata, and dependencies (cancellations/activations).
    /// It then persists this information in the database via [`Database::save_tx`] and related functions.
    /// The actual sending logic (CPFP/RBF) is handled later by the transaction sender's task loop.
    ///
    /// # Default Activation and Cancellation Conditions
    ///
    /// By default, this function automatically adds cancellation conditions for all outpoints
    /// spent by the `signed_tx` itself. If `signed_tx` confirms, these input outpoints
    /// are marked as spent/cancelled in the database.
    ///
    /// There are no default activation conditions added implicitly; all activation prerequisites
    /// must be explicitly provided via the `activate_txids` and `activate_outpoints` arguments.
    ///
    /// # Arguments
    /// * `dbtx` - An active database transaction.
    /// * `tx_metadata` - Optional metadata about the transaction's purpose.
    /// * `signed_tx` - The transaction to be potentially sent.
    /// * `fee_paying_type` - Whether to use CPFP or RBF for fee management.
    /// * `cancel_outpoints` - Outpoints that should be marked invalid if this tx confirms (in addition to the tx's own inputs).
    /// * `cancel_txids` - Txids that should be marked invalid if this tx confirms.
    /// * `activate_txids` - Txids that are prerequisites for this tx, potentially with a relative timelock.
    /// * `activate_outpoints` - Outpoints that are prerequisites for this tx, potentially with a relative timelock.
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
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
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

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(dbtx, try_to_send_id, input_outpoint)
                .await?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(dbtx, try_to_send_id, *outpoint)
                .await?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(dbtx, try_to_send_id, *txid)
                .await?;
        }

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

        for activated_outpoint in activate_outpoints {
            self.db
                .save_activated_outpoint(dbtx, try_to_send_id, activated_outpoint)
                .await?;
        }

        Ok(try_to_send_id)
    }
}
