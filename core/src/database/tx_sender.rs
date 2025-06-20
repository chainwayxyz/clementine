//! # Transaction Sender Related Database Operations
//!
//! This module includes database functions which are mainly used by the transaction sender.

use super::{wrapper::TxidDB, Database, DatabaseTransaction};
use crate::{
    errors::BridgeError,
    execute_query_with_tx,
    tx_sender::{ActivatedWithOutpoint, ActivatedWithTxid},
    utils::{FeePayingType, RbfSigningInfo, TxMetadata},
};
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, FeeRate, Transaction, Txid,
};
use eyre::{Context, OptionExt};
use sqlx::Executor;
use std::ops::DerefMut;

impl Database {
    /// Set all transactions' `seen_block_id` to the given block id. This will
    /// be called once a block is confirmed on the Bitcoin side.
    pub async fn confirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
    ) -> Result<(), BridgeError> {
        let block_id = i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?;

        // CTEs for collecting a block's transactions, spent UTXOs and confirmed
        // RBF transactions.
        let common_ctes = r#"
            WITH relevant_txs AS (
                SELECT txid
                FROM bitcoin_syncer_txs
                WHERE block_id = $1
            ),
            relevant_spent_utxos AS (
                SELECT txid, vout
                FROM bitcoin_syncer_spent_utxos
                WHERE block_id = $1
            ),
            confirmed_rbf_ids AS (
                SELECT rbf.id
                FROM tx_sender_rbf_txids AS rbf
                JOIN bitcoin_syncer_txs AS syncer ON rbf.txid = syncer.txid
                WHERE syncer.block_id = $1
            )
        "#;

        // Update tx_sender_activate_try_to_send_txids
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_activate_try_to_send_txids AS tap
            SET seen_block_id = $1
            WHERE tap.txid IN (SELECT txid FROM relevant_txs)
            AND tap.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_activate_try_to_send_outpoints
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_activate_try_to_send_outpoints AS tap
            SET seen_block_id = $1
            WHERE (tap.txid, tap.vout) IN (SELECT txid, vout FROM relevant_spent_utxos)
            AND tap.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_cancel_try_to_send_txids
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_cancel_try_to_send_txids AS ctt
            SET seen_block_id = $1
            WHERE ctt.txid IN (SELECT txid FROM relevant_txs)
            AND ctt.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_cancel_try_to_send_outpoints
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_cancel_try_to_send_outpoints AS cto
            SET seen_block_id = $1
            WHERE (cto.txid, cto.vout) IN (SELECT txid, vout FROM relevant_spent_utxos)
            AND cto.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_fee_payer_utxos
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_fee_payer_utxos AS fpu
            SET seen_block_id = $1
            WHERE fpu.fee_payer_txid IN (SELECT txid FROM relevant_txs)
            AND fpu.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_try_to_send_txs for CPFP txid confirmation
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = $1
            WHERE txs.txid IN (SELECT txid FROM relevant_txs)
            AND txs.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_try_to_send_txs for RBF txid confirmation
        sqlx::query(&format!(
            "{}
            UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = $1
            WHERE txs.id IN (SELECT id FROM confirmed_rbf_ids)
            AND txs.seen_block_id IS NULL",
            common_ctes
        ))
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        let bg_db = self.clone();
        // Update debug information in the background to not block core behavior
        tokio::spawn(async move {
            // Get confirmed direct transactions for debugging
            let Ok(confirmed_direct_txs): Result<Vec<(i32, TxidDB)>, _> = sqlx::query_as(&format!(
                "{}
            SELECT txs.id, txs.txid
            FROM tx_sender_try_to_send_txs AS txs
            WHERE txs.txid IN (SELECT txid FROM relevant_txs)
            AND txs.seen_block_id IS NULL",
                common_ctes
            ))
            .bind(block_id as i32)
            .fetch_all(&bg_db.connection)
            .await
            else {
                tracing::error!("Failed to update debug info for confirmed txs");
                return;
            };

            // Get confirmed RBF transactions for debugging
            let Ok(confirmed_rbf_txs): Result<Vec<(i32,)>, _> = sqlx::query_as(&format!(
                "{}
            SELECT txs.id
            FROM tx_sender_try_to_send_txs AS txs
            WHERE txs.id IN (SELECT id FROM confirmed_rbf_ids)
            AND txs.seen_block_id IS NULL",
                common_ctes
            ))
            .bind(block_id as i32)
            .fetch_all(&bg_db.connection)
            .await
            else {
                tracing::error!("Failed to update debug info for confirmed txs");
                return;
            };

            // Record debug info for confirmed transactions
            for (tx_id, txid) in confirmed_direct_txs {
                // Add debug state change
                tracing::debug!(try_to_send_id=?tx_id,  "Transaction confirmed in block {}: direct confirmation of txid {}",
            block_id, txid.0);

                // Update sending state
                let _ = bg_db
                    .update_tx_debug_sending_state(tx_id as u32, "confirmed", true)
                    .await;
            }

            // Record debug info for confirmed RBF transactions
            for (tx_id,) in confirmed_rbf_txs {
                // Add debug state change
                tracing::debug!(try_to_send_id=?tx_id,  "Transaction confirmed in block {}: RBF confirmation",
            block_id);

                // Update sending state
                let _ = bg_db
                    .update_tx_debug_sending_state(tx_id as u32, "confirmed", true)
                    .await;
            }
        });

        Ok(())
    }

    /// Unassigns `seen_block_id` from all transactions in the given block id.
    /// By default, all transactions' `seen_block_id` is set to NULL. And they
    /// get assigned a block id when they are confirmed on Bitcoin side. If a
    /// reorg happens, block ids must be unassigned from all transactions.
    pub async fn unconfirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
    ) -> Result<(), BridgeError> {
        let block_id = i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?;

        // Need to get these before they're unconfirmed below, so that we can update the debug info
        // Ignore the error here to not affect production behavior.
        let previously_confirmed_txs = sqlx::query_as::<_, (i32,)>(
            "SELECT id FROM tx_sender_try_to_send_txs WHERE seen_block_id = $1",
        )
        .bind(block_id)
        .fetch_all(tx.deref_mut())
        .await;

        let bg_db = self.clone();
        tokio::spawn(async move {
            let previously_confirmed_txs = match previously_confirmed_txs {
                Ok(txs) => txs,
                Err(e) => {
                    tracing::error!(error=?e, "Failed to get previously confirmed txs from database");
                    return;
                }
            };

            for (tx_id,) in previously_confirmed_txs {
                tracing::debug!(try_to_send_id=?tx_id, "Transaction unconfirmed in block {}: unconfirming", block_id);
                let _ = bg_db
                    .update_tx_debug_sending_state(tx_id as u32, "unconfirmed", false)
                    .await;
            }
        });

        // Unconfirm tx_sender_fee_payer_utxos
        // Update tx_sender_activate_try_to_send_txids
        sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_txids AS tap
             SET seen_block_id = NULL
             WHERE tap.seen_block_id = $1",
        )
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_activate_try_to_send_outpoints
        sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_outpoints AS tap
             SET seen_block_id = NULL
             WHERE tap.seen_block_id = $1",
        )
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_cancel_try_to_send_txids
        sqlx::query(
            "UPDATE tx_sender_cancel_try_to_send_txids AS ctt
             SET seen_block_id = NULL
             WHERE ctt.seen_block_id = $1",
        )
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_cancel_try_to_send_outpoints
        sqlx::query(
            "UPDATE tx_sender_cancel_try_to_send_outpoints AS cto
             SET seen_block_id = NULL
             WHERE cto.seen_block_id = $1",
        )
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_fee_payer_utxos
        sqlx::query(
            "UPDATE tx_sender_fee_payer_utxos AS fpu
             SET seen_block_id = NULL
             WHERE fpu.seen_block_id = $1",
        )
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        // Update tx_sender_try_to_send_txs
        sqlx::query(
            "UPDATE tx_sender_try_to_send_txs AS txs
             SET seen_block_id = NULL
             WHERE txs.seen_block_id = $1",
        )
        .bind(block_id)
        .execute(tx.deref_mut())
        .await?;

        Ok(())
    }

    /// Saves a fee payer transaction to the database.
    ///
    /// # Arguments
    /// * `bumped_id` - The id of the bumped transaction
    /// * `fee_payer_txid` - The txid of the fee payer transaction
    /// * `vout` - The output index of the UTXO
    /// * `script_pubkey` - The script pubkey of the UTXO
    /// * `amount` - The amount in satoshis
    pub async fn save_fee_payer_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        bumped_id: u32,
        fee_payer_txid: Txid,
        vout: u32,
        amount: Amount,
        replacement_of_id: Option<u32>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_fee_payer_utxos (bumped_id, fee_payer_txid, vout, amount, replacement_of_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(i32::try_from(bumped_id).wrap_err("Failed to convert bumped id to i32")?)
        .bind(TxidDB(fee_payer_txid))
        .bind(i32::try_from(vout).wrap_err("Failed to convert vout to i32")?)
        .bind(i64::try_from(amount.to_sat()).wrap_err("Failed to convert amount to i64")?)
        .bind(replacement_of_id.map( i32::try_from).transpose().wrap_err("Failed to convert replacement of id to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Returns all unconfirmed fee payer transactions for a try-to-send tx.
    /// Replaced (bumped) fee payers are not included.
    ///
    /// # Parameters
    ///
    /// - `bumped_id`: The id of the bumped transaction
    ///
    /// # Returns
    ///
    /// A vector of unconfirmed fee payer transaction details, including:
    ///
    /// - [`u32`]: Id of the fee payer transaction.
    /// - [`Txid`]: Txid of the fee payer transaction.
    /// - [`u32`]: Output index of the UTXO.
    /// - [`Amount`]: Amount in satoshis.
    pub async fn get_unconfirmed_fee_payer_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        bumped_id: u32,
    ) -> Result<Vec<(u32, Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB, i32, i64)>(
            "
            SELECT fpu.id, fpu.fee_payer_txid, fpu.vout, fpu.amount
            FROM tx_sender_fee_payer_utxos fpu
            WHERE fpu.bumped_id = $1
              AND fpu.seen_block_id IS NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM tx_sender_fee_payer_utxos replacement
                  WHERE replacement.replacement_of_id = fpu.id
              )
            ",
        )
        .bind(i32::try_from(bumped_id).wrap_err("Failed to convert bumped id to i32")?);

        let results: Vec<(i32, TxidDB, i32, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .iter()
            .map(|(id, fee_payer_txid, vout, amount)| {
                Ok((
                    u32::try_from(*id).wrap_err("Failed to convert id to u32")?,
                    fee_payer_txid.0,
                    u32::try_from(*vout).wrap_err("Failed to convert vout to u32")?,
                    Amount::from_sat(
                        u64::try_from(*amount).wrap_err("Failed to convert amount to u64")?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: u32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64)>(
            "SELECT fee_payer_txid, vout, amount
             FROM tx_sender_fee_payer_utxos fpu
             WHERE fpu.bumped_id = $1 AND fpu.seen_block_id IS NOT NULL",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let results: Vec<(TxidDB, i32, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .iter()
            .map(|(fee_payer_txid, vout, amount)| {
                Ok((
                    fee_payer_txid.0,
                    u32::try_from(*vout).wrap_err("Failed to convert vout to u32")?,
                    Amount::from_sat(
                        u64::try_from(*amount).wrap_err("Failed to convert amount to u64")?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn save_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        tx_metadata: Option<TxMetadata>,
        raw_tx: &Transaction,
        fee_paying_type: FeePayingType,
        txid: Txid,
        rbf_signing_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO tx_sender_try_to_send_txs (raw_tx, fee_paying_type, tx_metadata, txid, rbf_signing_info) VALUES ($1, $2::fee_paying_type, $3, $4, $5) RETURNING id"
        )
        .bind(serialize(raw_tx))
        .bind(fee_paying_type)
        .bind(serde_json::to_string(&tx_metadata).wrap_err("Failed to encode tx_metadata to JSON")?)
        .bind(TxidDB(txid))
        .bind(serde_json::to_string(&rbf_signing_info).wrap_err("Failed to encode tx_metadata to JSON")?);

        let id: i32 = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        u32::try_from(id)
            .wrap_err("Failed to convert id to u32")
            .map_err(Into::into)
    }

    pub async fn save_rbf_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: u32,
        txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO tx_sender_rbf_txids (id, txid) VALUES ($1, $2)")
            .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?)
            .bind(TxidDB(txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_last_rbf_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: u32,
    ) -> Result<Option<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB,)>("SELECT txid FROM tx_sender_rbf_txids WHERE id = $1 ORDER BY insertion_order DESC LIMIT 1")
            .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let result: Option<(TxidDB,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(result.map(|(txid,)| txid.0))
    }

    pub async fn save_cancelled_outpoint(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        cancelled_id: u32,
        outpoint: bitcoin::OutPoint,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_cancel_try_to_send_outpoints (cancelled_id, txid, vout) VALUES ($1, $2, $3)"
        )
        .bind(i32::try_from(cancelled_id).wrap_err("Failed to convert cancelled id to i32")?)
        .bind(TxidDB(outpoint.txid))
        .bind(i32::try_from(outpoint.vout).wrap_err("Failed to convert vout to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn save_cancelled_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        cancelled_id: u32,
        txid: bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_cancel_try_to_send_txids (cancelled_id, txid) VALUES ($1, $2)",
        )
        .bind(i32::try_from(cancelled_id).wrap_err("Failed to convert cancelled id to i32")?)
        .bind(TxidDB(txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn save_activated_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        activated_id: u32,
        prerequisite_tx: &ActivatedWithTxid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_activate_try_to_send_txids (activated_id, txid, timelock) VALUES ($1, $2, $3)"
        )
        .bind(i32::try_from(activated_id).wrap_err("Failed to convert activated id to i32")?)
        .bind(TxidDB(prerequisite_tx.txid))
        .bind(i32::try_from(prerequisite_tx.relative_block_height).wrap_err("Failed to convert relative block height to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn save_activated_outpoint(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        activated_id: u32,
        activated_outpoint: &ActivatedWithOutpoint,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_activate_try_to_send_outpoints (activated_id, txid, vout, timelock) VALUES ($1, $2, $3, $4)"
        )
        .bind(i32::try_from(activated_id).wrap_err("Failed to convert activated id to i32")?)
        .bind(TxidDB(activated_outpoint.outpoint.txid))
        .bind(i32::try_from(activated_outpoint.outpoint.vout).wrap_err("Failed to convert vout to i32")?)
        .bind(i32::try_from(activated_outpoint.relative_block_height).wrap_err("Failed to convert relative block height to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    /// Returns unconfirmed try-to-send transactions that satisfy all activation
    /// conditions for sending:
    ///
    /// - Not in the non-active list
    /// - Not in the cancelled list
    /// - Transaction itself is not already confirmed
    /// - Transaction and UTXO timelocks must be passed
    /// - Fee rate is lower than the provided fee rate or null (deprecated)
    ///
    /// # Parameters
    ///
    /// - `tx`: Optional database transaction
    /// - `fee_rate`: Maximum fee rate for the transactions to be sendable
    /// - `current_tip_height`: The current tip height of the Bitcoin blockchain
    ///   for checking timelocks
    ///
    /// # Returns
    ///
    /// - [`Vec<u32>`]: A vector of transaction ids (db id) that are sendable.
    pub async fn get_sendable_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<Vec<u32>, BridgeError> {
        let select_query = sqlx::query_as::<_, (i32,)>(
            "WITH
                -- Find non-active transactions (not seen or timelock not passed)
                non_active_txs AS (
                    -- Transactions with txid activations that aren't active yet
                    SELECT DISTINCT
                        activate_txid.activated_id AS tx_id
                    FROM
                        tx_sender_activate_try_to_send_txids AS activate_txid
                    LEFT JOIN
                        bitcoin_syncer AS syncer ON activate_txid.seen_block_id = syncer.id
                    WHERE
                        activate_txid.seen_block_id IS NULL
                        OR (syncer.height + activate_txid.timelock > $2)

                    UNION

                    -- Transactions with outpoint activations that aren't active yet (not seen or timelock not passed)
                    SELECT DISTINCT
                        activate_outpoint.activated_id AS tx_id
                    FROM
                        tx_sender_activate_try_to_send_outpoints AS activate_outpoint
                    LEFT JOIN
                        bitcoin_syncer AS syncer ON activate_outpoint.seen_block_id = syncer.id
                    WHERE
                        activate_outpoint.seen_block_id IS NULL
                        OR (syncer.height + activate_outpoint.timelock > $2)
                ),

                -- Transactions with cancelled conditions
                cancelled_txs AS (
                    -- Transactions with cancelled outpoints (not seen)
                    SELECT DISTINCT
                        cancelled_id AS tx_id
                    FROM
                        tx_sender_cancel_try_to_send_outpoints
                    WHERE
                        seen_block_id IS NOT NULL

                    UNION

                    -- Transactions with cancelled txids (not seen)
                    SELECT DISTINCT
                        cancelled_id AS tx_id
                    FROM
                        tx_sender_cancel_try_to_send_txids
                    WHERE
                        seen_block_id IS NOT NULL
                )

                -- Final query to get sendable transactions
                SELECT
                    txs.id
                FROM
                    tx_sender_try_to_send_txs AS txs
                WHERE
                    -- Transaction must not be in the non-active list
                    txs.id NOT IN (SELECT tx_id FROM non_active_txs)
                    -- Transaction must not be in the cancelled list
                    AND txs.id NOT IN (SELECT tx_id FROM cancelled_txs)
                    -- Transaction must not be already confirmed
                    AND txs.seen_block_id IS NULL
                    -- Check if fee_rate is lower than the provided fee rate or null
                    AND (txs.effective_fee_rate IS NULL OR txs.effective_fee_rate < $1);",
        )
        .bind(
            i64::try_from(fee_rate.to_sat_per_vb_ceil())
                .wrap_err("Failed to convert fee rate to i64")?,
        )
        .bind(
            i32::try_from(current_tip_height)
                .wrap_err("Failed to convert current tip height to i32")?,
        );

        let results = execute_query_with_tx!(self.connection, tx, select_query, fetch_all)?;

        let txs = results
            .into_iter()
            .map(|(id,)| u32::try_from(id))
            .collect::<Result<Vec<_>, _>>()
            .wrap_err("Failed to convert id to u32")?;

        Ok(txs)
    }

    pub async fn update_effective_fee_rate(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: u32,
        effective_fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs SET effective_fee_rate = $1 WHERE id = $2",
        )
        .bind(
            i64::try_from(effective_fee_rate.to_sat_per_vb_ceil())
                .wrap_err("Failed to convert effective fee rate to i64")?,
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_try_to_send_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: u32,
    ) -> Result<
        (
            Option<TxMetadata>,
            Transaction,
            FeePayingType,
            Option<u32>,
            Option<RbfSigningInfo>,
        ),
        BridgeError,
    > {
        let query = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<Vec<u8>>,
                FeePayingType,
                Option<i32>,
                Option<String>,
            ),
        >(
            "SELECT tx_metadata, raw_tx, fee_paying_type, seen_block_id, rbf_signing_info
             FROM tx_sender_try_to_send_txs
             WHERE id = $1 LIMIT 1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok((
            serde_json::from_str(result.0.as_deref().unwrap_or("null"))
                .wrap_err_with(|| format!("Failed to decode tx_metadata from {:?}", result.0))?,
            result
                .1
                .as_deref()
                .map(deserialize)
                .ok_or_eyre("Expected raw_tx to be present")?
                .wrap_err("Failed to deserialize raw_tx")?,
            result.2,
            result
                .3
                .map(u32::try_from)
                .transpose()
                .wrap_err("Failed to convert seen_block_id to u32")?,
            serde_json::from_str(result.4.as_deref().unwrap_or("null")).wrap_err_with(|| {
                format!("Failed to decode rbf_signing_info from {:?}", result.4)
            })?,
        ))
    }

    // Debug Functions

    /// Saves a TX submission error to the debug table
    pub async fn save_tx_debug_submission_error(
        &self,
        tx_id: u32,
        error_message: &str,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_debug_submission_errors (tx_id, error_message) VALUES ($1, $2)",
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?)
        .bind(error_message);

        self.connection.execute(query).await?;
        Ok(())
    }

    /// Updates or inserts the TX's sending state in the debug table
    ///
    /// Does not support a Transaction because it's for debugging purposes. Make
    /// sure that tx_id exists (i.e. creation is committed) before use
    pub async fn update_tx_debug_sending_state(
        &self,
        tx_id: u32,
        state: &str,
        activated: bool,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            r#"
            INSERT INTO tx_sender_debug_sending_state
            (tx_id, state, last_update, activated_timestamp)
            VALUES ($1, $2, NOW(),
                CASE
                    WHEN $3 = TRUE THEN NOW()
                    ELSE NULL
                END
            )
            ON CONFLICT (tx_id) DO UPDATE SET
            state = $2,
            last_update = NOW(),
            activated_timestamp = COALESCE(tx_sender_debug_sending_state.activated_timestamp,
                CASE
                    WHEN $3 = TRUE THEN NOW()
                    ELSE NULL
                END
            )
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?)
        .bind(state)
        .bind(activated);

        self.connection.execute(query).await?;
        Ok(())
    }

    /// Gets the current debug state of a TX
    pub async fn get_tx_debug_info(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        tx_id: u32,
    ) -> Result<Option<String>, BridgeError> {
        let query = sqlx::query_as::<_, (Option<String>,)>(
            r#"
            SELECT state
            FROM tx_sender_debug_sending_state
            WHERE tx_id = $1
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        match result {
            Some((state,)) => Ok(state),
            None => Ok(None),
        }
    }

    /// Gets all TX submission errors
    pub async fn get_tx_debug_submission_errors(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        tx_id: u32,
    ) -> Result<Vec<(String, String)>, BridgeError> {
        let query = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT error_message, timestamp::TEXT
            FROM tx_sender_debug_submission_errors
            WHERE tx_id = $1
            ORDER BY timestamp ASC
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

        execute_query_with_tx!(self.connection, tx, query, fetch_all).map_err(Into::into)
    }

    /// Gets all fee payer UTXOs for a TX with their confirmation status
    pub async fn get_tx_debug_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        tx_id: u32,
    ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64, Option<i32>)>(
            r#"
            SELECT fee_payer_txid, vout, amount, (seen_block_id IS NOT NULL)::INT4 as confirmed
            FROM tx_sender_fee_payer_utxos
            WHERE bumped_id = $1
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

        let results: Vec<(TxidDB, i32, i64, Option<i32>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .iter()
            .map(|(fee_payer_txid, vout, amount, confirmed)| {
                Ok((
                    fee_payer_txid.0,
                    u32::try_from(*vout).wrap_err("Failed to convert vout to u32")?,
                    Amount::from_sat(
                        u64::try_from(*amount).wrap_err("Failed to convert amount to u64")?,
                    ),
                    confirmed.is_some(),
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    /// Purges debug information for a successfully sent TX
    pub async fn purge_tx_debug_info(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        tx_id: u32,
    ) -> Result<(), BridgeError> {
        let queries = [
            "DELETE FROM tx_sender_debug_state_changes WHERE tx_id = $1",
            "DELETE FROM tx_sender_debug_submission_errors WHERE tx_id = $1",
            "DELETE FROM tx_sender_debug_sending_state WHERE tx_id = $1",
        ];

        for query_str in queries {
            let query = sqlx::query(query_str)
                .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

            execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;
        }

        Ok(())
    }

    #[cfg(test)]
    pub async fn debug_inactive_txs(&self, fee_rate: FeeRate, current_tip_height: u32) {
        tracing::info!("TXSENDER_DBG_INACTIVE_TXS: Checking inactive transactions");

        // Query all transactions that aren't confirmed yet
        let unconfirmed_txs = match sqlx::query_as::<_, (i32, TxidDB, Option<String>)>(
            "SELECT id, txid, tx_metadata FROM tx_sender_try_to_send_txs WHERE seen_block_id IS NULL",
        )
        .fetch_all(&self.connection)
        .await
        {
            Ok(txs) => txs,
            Err(e) => {
                tracing::error!(
                    "TXSENDER_DBG_INACTIVE_TXS: Failed to query unconfirmed txs: {}",
                    e
                );
                return;
            }
        };

        let sendable_txs = match self
            .get_sendable_txs(None, fee_rate, current_tip_height)
            .await
        {
            Ok(txs) => txs,
            Err(e) => {
                tracing::error!(
                    "TXSENDER_DBG_INACTIVE_TXS: Failed to get sendable txs: {}",
                    e
                );
                return;
            }
        };

        for (tx_id, txid, tx_metadata) in unconfirmed_txs {
            let tx_metadata: Option<TxMetadata> =
                serde_json::from_str(tx_metadata.as_deref().unwrap_or("null")).ok();

            let id = match u32::try_from(tx_id) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("TXSENDER_DBG_INACTIVE_TXS: Failed to convert id: {}", e);
                    continue;
                }
            };

            if sendable_txs.contains(&id) {
                tracing::info!(
                    "TXSENDER_DBG_INACTIVE_TXS: TX {} (txid: {}) is ACTIVE",
                    id,
                    txid.0
                );
                continue;
            }

            tracing::info!(
                "TXSENDER_DBG_INACTIVE_TXS: TX {} (txid: {}, type: {:?}) is inactive, reasons:",
                id,
                txid.0,
                tx_metadata.map(|metadata| metadata.tx_type)
            );

            // Check for txid activations that aren't active yet
            let txid_activations = match sqlx::query_as::<_, (Option<i32>, i64, TxidDB)>(
                "SELECT seen_block_id, timelock, txid
                FROM tx_sender_activate_try_to_send_txids
                WHERE activated_id = $1",
            )
            .bind(tx_id)
            .fetch_all(&self.connection)
            .await
            {
                Ok(activations) => activations,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query txid activations: {}",
                        e
                    );
                    continue;
                }
            };

            for (seen_block_id, timelock, txid) in txid_activations {
                if seen_block_id.is_none() {
                    tracing::info!("TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its txid activation {} has not been seen", id, txid.0);
                    continue;
                }

                let block_height = match sqlx::query_scalar::<_, i32>(
                    "SELECT height FROM bitcoin_syncer WHERE id = $1",
                )
                .bind(seen_block_id.unwrap())
                .fetch_one(&self.connection)
                .await
                {
                    Ok(height) => height,
                    Err(e) => {
                        tracing::error!(
                            "TXSENDER_DBG_INACTIVE_TXS: Failed to get block height: {}",
                            e
                        );
                        continue;
                    }
                };

                if block_height + timelock as i32 > current_tip_height as i32 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its txid activation timelock hasn't expired (block_height: {}, timelock: {}, current_tip_height: {})",
                        id, block_height, timelock, current_tip_height
                    );
                }
            }

            // Check for outpoint activations that aren't active yet
            let outpoint_activations = match sqlx::query_as::<_, (Option<i32>, i64, TxidDB, i32)>(
                "SELECT seen_block_id, timelock, txid, vout
                FROM tx_sender_activate_try_to_send_outpoints
                WHERE activated_id = $1",
            )
            .bind(tx_id)
            .fetch_all(&self.connection)
            .await
            {
                Ok(activations) => activations,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query outpoint activations: {}",
                        e
                    );
                    continue;
                }
            };

            for (seen_block_id, timelock, txid, vout) in outpoint_activations {
                if seen_block_id.is_none() {
                    tracing::info!("TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its outpoint activation has not been seen ({}:{})", id, txid.0, vout);
                    continue;
                }

                let block_height = match sqlx::query_scalar::<_, i32>(
                    "SELECT height FROM bitcoin_syncer WHERE id = $1",
                )
                .bind(seen_block_id.unwrap())
                .fetch_one(&self.connection)
                .await
                {
                    Ok(height) => height,
                    Err(e) => {
                        tracing::error!(
                            "TXSENDER_DBG_INACTIVE_TXS: Failed to get block height: {}",
                            e
                        );
                        continue;
                    }
                };

                if block_height + timelock as i32 > current_tip_height as i32 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its outpoint activation timelock hasn't expired (block_height: {}, timelock: {}, current_tip_height: {})",
                        id, block_height, timelock, current_tip_height
                    );
                }
            }

            // Check for cancelled conditions
            let cancelled_outpoints = match sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM tx_sender_cancel_try_to_send_outpoints
                WHERE cancelled_id = $1 AND seen_block_id IS NOT NULL",
            )
            .bind(tx_id)
            .fetch_one(&self.connection)
            .await
            {
                Ok(count) => count,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query cancelled outpoints: {}",
                        e
                    );
                    continue;
                }
            };

            if cancelled_outpoints > 0 {
                tracing::info!("TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because it has {} cancelled outpoints", id, cancelled_outpoints);
            }

            let cancelled_txids = match sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM tx_sender_cancel_try_to_send_txids
                WHERE cancelled_id = $1 AND seen_block_id IS NOT NULL",
            )
            .bind(tx_id)
            .fetch_one(&self.connection)
            .await
            {
                Ok(count) => count,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query cancelled txids: {}",
                        e
                    );
                    continue;
                }
            };

            if cancelled_txids > 0 {
                tracing::info!("TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because it has {} cancelled txids", id, cancelled_txids);
            }

            // Check fee rate
            let effective_fee_rate = match sqlx::query_scalar::<_, Option<i64>>(
                "SELECT effective_fee_rate FROM tx_sender_try_to_send_txs WHERE id = $1",
            )
            .bind(tx_id)
            .fetch_one(&self.connection)
            .await
            {
                Ok(rate) => rate,
                Err(e) => {
                    tracing::error!(
                        "TXSENDER_DBG_INACTIVE_TXS: Failed to query effective fee rate: {}",
                        e
                    );
                    continue;
                }
            };

            if let Some(rate) = effective_fee_rate {
                if rate >= fee_rate.to_sat_per_vb_ceil() as i64 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its effective fee rate ({} sat/vB) is >= the current fee rate ({} sat/vB)",
                        id, rate, fee_rate.to_sat_per_vb_ceil()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test::common::*;

    use super::*;
    use crate::database::Database;
    use bitcoin::absolute::Height;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Block, OutPoint, TapNodeHash, Txid};

    async fn setup_test_db() -> Database {
        let config = create_test_config_with_thread_name().await;
        Database::new(&config).await.unwrap()
    }

    #[tokio::test]
    async fn test_save_and_get_tx() {
        let db = setup_test_db().await;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };

        // Test saving tx
        let txid = tx.compute_txid();
        let rbfinfo = Some(RbfSigningInfo {
            vout: 123,
            tweak_merkle_root: Some(TapNodeHash::all_zeros()),
        });
        let id = db
            .save_tx(None, None, &tx, FeePayingType::CPFP, txid, rbfinfo.clone())
            .await
            .unwrap();

        // Test retrieving tx
        let (_, retrieved_tx, fee_paying_type, seen_block_id, rbf_signing_info) =
            db.get_try_to_send_tx(None, id).await.unwrap();
        assert_eq!(tx.version, retrieved_tx.version);
        assert_eq!(fee_paying_type, FeePayingType::CPFP);
        assert_eq!(seen_block_id, None);
        assert_eq!(rbf_signing_info, rbfinfo);
    }

    #[tokio::test]
    async fn test_fee_payer_utxo_operations() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // First create a transaction that will be bumped
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };

        // Save the transaction first
        let tx_id = db
            .save_tx(
                Some(&mut dbtx),
                None,
                &tx,
                FeePayingType::CPFP,
                Txid::all_zeros(),
                None,
            )
            .await
            .unwrap();

        // Now we can use this tx_id as bumped_id
        let fee_payer_txid = Txid::hash(&[1u8; 32]);
        db.save_fee_payer_tx(
            Some(&mut dbtx),
            tx_id,
            fee_payer_txid,
            0,
            Amount::from_sat(50000),
            None,
        )
        .await
        .unwrap();

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_confirm_and_unconfirm_transactions() {
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex::decode(BLOCK_HEX).unwrap()).unwrap();

        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // Create a block to use for confirmation
        let block_id = crate::bitcoin_syncer::save_block(&db, &mut dbtx, &block, 100)
            .await
            .unwrap();

        // Create a transaction
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };
        let tx_id = db
            .save_tx(
                Some(&mut dbtx),
                None,
                &tx,
                FeePayingType::CPFP,
                Txid::all_zeros(),
                None,
            )
            .await
            .unwrap();

        // Save fee payer UTXO
        let fee_payer_txid = Txid::hash(&[1u8; 32]);
        db.save_fee_payer_tx(
            Some(&mut dbtx),
            tx_id,
            fee_payer_txid,
            0,
            Amount::from_sat(50000),
            None,
        )
        .await
        .unwrap();

        // Save the transaction in the block
        db.add_txid_to_block(&mut dbtx, block_id, &fee_payer_txid)
            .await
            .unwrap();

        // Confirm transactions
        db.confirm_transactions(&mut dbtx, block_id).await.unwrap();

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_cancelled_outpoints_and_txids() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // First create a transaction to cancel
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };

        // Save the transaction first
        let tx_id = db
            .save_tx(
                Some(&mut dbtx),
                None,
                &tx,
                FeePayingType::CPFP,
                Txid::all_zeros(),
                None,
            )
            .await
            .unwrap();

        // Now we can use this tx_id as cancelled_id
        let txid = Txid::hash(&[0u8; 32]);
        let vout = 0;

        // Test cancelling by outpoint
        db.save_cancelled_outpoint(Some(&mut dbtx), tx_id, OutPoint { txid, vout })
            .await
            .unwrap();

        // Test cancelling by txid
        db.save_cancelled_txid(Some(&mut dbtx), tx_id, txid)
            .await
            .unwrap();

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_get_sendable_txs() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // Create and save test transactions
        let tx1 = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };
        let tx2 = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };

        let id1 = db
            .save_tx(
                Some(&mut dbtx),
                None,
                &tx1,
                FeePayingType::CPFP,
                Txid::all_zeros(),
                None,
            )
            .await
            .unwrap();
        let id2 = db
            .save_tx(
                Some(&mut dbtx),
                None,
                &tx2,
                FeePayingType::RBF,
                Txid::all_zeros(),
                None,
            )
            .await
            .unwrap();

        // Test getting sendable txs
        let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        let current_tip_height = 100;
        let sendable_txs = db
            .get_sendable_txs(Some(&mut dbtx), fee_rate, current_tip_height)
            .await
            .unwrap();

        // Both transactions should be sendable as they have no prerequisites or cancellations
        assert_eq!(sendable_txs.len(), 2);
        assert!(sendable_txs.contains(&id1));
        assert!(sendable_txs.contains(&id2));

        // Test updating effective fee rate for tx1 with a fee rate equal to the query fee rate
        // This should  make tx1 not sendable since the condition is "effective_fee_rate < fee_rate"
        db.update_effective_fee_rate(Some(&mut dbtx), id1, fee_rate)
            .await
            .unwrap();

        let sendable_txs = db
            .get_sendable_txs(Some(&mut dbtx), fee_rate, current_tip_height)
            .await
            .unwrap();
        assert_eq!(sendable_txs.len(), 1);
        assert!(sendable_txs.contains(&id2));

        // Update tx1's effective fee rate to be higher than the query fee rate
        let higher_fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
        db.update_effective_fee_rate(Some(&mut dbtx), id1, higher_fee_rate)
            .await
            .unwrap();

        // Now only tx2 should be sendable since tx1's effective fee rate is higher than the query fee rate
        let sendable_txs = db
            .get_sendable_txs(Some(&mut dbtx), fee_rate, current_tip_height)
            .await
            .unwrap();
        assert_eq!(sendable_txs.len(), 1);
        assert!(sendable_txs.contains(&id2));

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_debug_sending_state() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // Create a test transaction
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };

        // Insert the transaction into the database
        let tx_id = db
            .save_tx(
                None, // needed so that tx_id is available
                None,
                &tx,
                FeePayingType::RBF,
                tx.compute_txid(),
                None,
            )
            .await
            .unwrap();

        // Test updating the sending state
        let initial_state = "waiting_for_fee_payer_utxos";
        db.update_tx_debug_sending_state(tx_id, initial_state, false)
            .await
            .unwrap();

        // Verify the state was saved correctly
        let state = db.get_tx_debug_info(Some(&mut dbtx), tx_id).await.unwrap();
        assert_eq!(state, Some(initial_state.to_string()));

        // Update the state with activation
        let active_state = "ready_to_send";
        db.update_tx_debug_sending_state(tx_id, active_state, true)
            .await
            .unwrap();

        // Verify the state was updated
        let state = db.get_tx_debug_info(Some(&mut dbtx), tx_id).await.unwrap();
        assert_eq!(state, Some(active_state.to_string()));

        // Test saving an error message
        let error_message = "Failed to send transaction: insufficient fee";
        db.save_tx_debug_submission_error(tx_id, error_message)
            .await
            .unwrap();

        // Verify the error was saved
        let errors = db
            .get_tx_debug_submission_errors(Some(&mut dbtx), tx_id)
            .await
            .unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, error_message);

        // Add another error
        let second_error = "Network connection timeout";
        db.save_tx_debug_submission_error(tx_id, second_error)
            .await
            .unwrap();

        // Verify both errors are retrieved in order
        let errors = db
            .get_tx_debug_submission_errors(Some(&mut dbtx), tx_id)
            .await
            .unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].0, error_message);
        assert_eq!(errors[1].0, second_error);

        // Update state again
        let final_state = "sent";
        db.update_tx_debug_sending_state(tx_id, final_state, true)
            .await
            .unwrap();

        // Verify final state
        let state = db.get_tx_debug_info(Some(&mut dbtx), tx_id).await.unwrap();
        assert_eq!(state, Some(final_state.to_string()));

        dbtx.commit().await.unwrap();
    }
}
