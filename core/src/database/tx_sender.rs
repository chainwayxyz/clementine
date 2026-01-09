//! This module includes database functions which are mainly used by the transaction sender.

use async_trait::async_trait;

use super::{wrapper::TxidDB, Database, DatabaseTransaction};
use crate::execute_query_with_tx;
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, FeeRate, Transaction, Txid,
};
use clementine_errors::BridgeError;
use clementine_tx_sender::{ActivatedWithOutpoint, ActivatedWithTxid};
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::{Context, OptionExt};
use sqlx::Executor;

impl Database {
    /// Synchronizes transaction confirmations based on canonical block status.
    /// Confirms transactions in canonical blocks and unconfirms transactions in
    /// non-canonical blocks. This handles both new confirmations/unconfirmations
    /// and any previously missed updates due to race conditions.
    pub async fn sync_transaction_confirmations(
        &self,
        mut tx: Option<DatabaseTransaction<'_>>,
    ) -> Result<(), BridgeError> {
        // Confirm all transactions that are in canonical blocks
        let query1 = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_txids AS tap
            SET seen_block_id = bs.id
            FROM bitcoin_syncer_txs bst
            JOIN bitcoin_syncer bs ON bst.block_id = bs.id
            WHERE tap.txid = bst.txid
            AND tap.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query1, execute)?;

        let query2 = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_outpoints AS tap
            SET seen_block_id = bs.id
            FROM bitcoin_syncer_spent_utxos bsu
            JOIN bitcoin_syncer bs ON bsu.block_id = bs.id
            WHERE tap.txid = bsu.txid
            AND tap.vout = bsu.vout
            AND tap.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query2, execute)?;

        let query3 = sqlx::query(
            "UPDATE tx_sender_cancel_try_to_send_txids AS ctt
            SET seen_block_id = bs.id
            FROM bitcoin_syncer_txs bst
            JOIN bitcoin_syncer bs ON bst.block_id = bs.id
            WHERE ctt.txid = bst.txid
            AND ctt.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query3, execute)?;

        let query4 = sqlx::query(
            "UPDATE tx_sender_cancel_try_to_send_outpoints AS cto
            SET seen_block_id = bs.id
            FROM bitcoin_syncer_spent_utxos bsu
            JOIN bitcoin_syncer bs ON bsu.block_id = bs.id
            WHERE cto.txid = bsu.txid
            AND cto.vout = bsu.vout
            AND cto.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query4, execute)?;

        let query5 = sqlx::query(
            "UPDATE tx_sender_fee_payer_utxos AS fpu
            SET seen_block_id = bs.id
            FROM bitcoin_syncer_txs bst
            JOIN bitcoin_syncer bs ON bst.block_id = bs.id
            WHERE fpu.fee_payer_txid = bst.txid
            AND fpu.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query5, execute)?;

        let query6 = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = bs.id
            FROM bitcoin_syncer_txs bst
            JOIN bitcoin_syncer bs ON bst.block_id = bs.id
            WHERE txs.txid = bst.txid
            AND txs.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query6, execute)?;

        // Handle RBF confirmations: if any RBF txid is confirmed, mark the parent transaction
        let query7 = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = bs.id
            FROM tx_sender_rbf_txids AS rbf
            JOIN bitcoin_syncer_txs AS bst ON rbf.txid = bst.txid
            JOIN bitcoin_syncer bs ON bst.block_id = bs.id
            WHERE txs.id = rbf.id
            AND txs.seen_block_id IS NULL
            AND bs.is_canonical = TRUE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query7, execute)?;

        // Unconfirm all transactions that reference non-canonical blocks
        let query8 = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_txids AS tap
            SET seen_block_id = NULL
            FROM bitcoin_syncer bs
            WHERE tap.seen_block_id = bs.id
            AND bs.is_canonical = FALSE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query8, execute)?;

        let query9 = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_outpoints AS tap
            SET seen_block_id = NULL
            FROM bitcoin_syncer bs
            WHERE tap.seen_block_id = bs.id
            AND bs.is_canonical = FALSE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query9, execute)?;

        let query10 = sqlx::query(
            "UPDATE tx_sender_cancel_try_to_send_txids AS ctt
            SET seen_block_id = NULL
            FROM bitcoin_syncer bs
            WHERE ctt.seen_block_id = bs.id
            AND bs.is_canonical = FALSE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query10, execute)?;

        let query11 = sqlx::query(
            "UPDATE tx_sender_cancel_try_to_send_outpoints AS cto
            SET seen_block_id = NULL
            FROM bitcoin_syncer bs
            WHERE cto.seen_block_id = bs.id
            AND bs.is_canonical = FALSE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query11, execute)?;

        let query12 = sqlx::query(
            "UPDATE tx_sender_fee_payer_utxos AS fpu
            SET seen_block_id = NULL
            FROM bitcoin_syncer bs
            WHERE fpu.seen_block_id = bs.id
            AND bs.is_canonical = FALSE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query12, execute)?;

        let query13 = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = NULL
            FROM bitcoin_syncer bs
            WHERE txs.seen_block_id = bs.id
            AND bs.is_canonical = FALSE",
        );
        execute_query_with_tx!(self.connection, tx.as_deref_mut(), query13, execute)?;

        // Handle RBF unconfirmations: unconfirm the parent transaction if
        // it has RBF txids and ALL of them are unconfirmed
        let query14 = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = NULL
            WHERE txs.seen_block_id IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM tx_sender_rbf_txids AS rbf
                WHERE rbf.id = txs.id
            )
            AND NOT EXISTS (
                SELECT 1 FROM tx_sender_rbf_txids AS rbf
                JOIN bitcoin_syncer_txs AS bst ON rbf.txid = bst.txid
                JOIN bitcoin_syncer bs ON bst.block_id = bs.id
                WHERE rbf.id = txs.id
                AND bs.is_canonical = TRUE
            )",
        );
        execute_query_with_tx!(self.connection, tx, query14, execute)?;

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
        tx: Option<DatabaseTransaction<'_>>,
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
    /// Transactions whose replacements are confirmed are not included. But if none of the replacements are confirmed, all replacements are returned.
    ///
    /// # Parameters
    ///
    /// # Returns
    ///
    /// A vector of unconfirmed fee payer transaction details, including:
    ///
    /// - [`u32`]: Id of the fee payer transaction.
    /// - [`u32`]: Id of the bumped transaction.
    /// - [`Txid`]: Txid of the fee payer transaction.
    /// - [`u32`]: Output index of the UTXO.
    /// - [`Amount`]: Amount in satoshis.
    pub async fn get_all_unconfirmed_fee_payer_txs(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
    ) -> Result<Vec<(u32, u32, Txid, u32, Amount, Option<u32>)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, i32, TxidDB, i32, i64, Option<i32>)>(
            "
            SELECT fpu.id, fpu.bumped_id, fpu.fee_payer_txid, fpu.vout, fpu.amount, fpu.replacement_of_id
            FROM tx_sender_fee_payer_utxos fpu
            WHERE fpu.seen_block_id IS NULL
              AND fpu.is_evicted = false
              AND NOT EXISTS (
                  SELECT 1
                  FROM tx_sender_fee_payer_utxos x
                  WHERE (x.replacement_of_id = fpu.replacement_of_id OR x.id = fpu.replacement_of_id)
                    AND x.seen_block_id IS NOT NULL
              )
            ",
        );

        let results: Vec<(i32, i32, TxidDB, i32, i64, Option<i32>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .iter()
            .map(
                |(id, bumped_id, fee_payer_txid, vout, amount, replacement_of_id)| {
                    Ok((
                        u32::try_from(*id).wrap_err("Failed to convert id to u32")?,
                        u32::try_from(*bumped_id).wrap_err("Failed to convert bumped id to u32")?,
                        fee_payer_txid.0,
                        u32::try_from(*vout).wrap_err("Failed to convert vout to u32")?,
                        Amount::from_sat(
                            u64::try_from(*amount).wrap_err("Failed to convert amount to u64")?,
                        ),
                        replacement_of_id
                            .map(u32::try_from)
                            .transpose()
                            .wrap_err("Failed to convert replacement of id to u32")?,
                    ))
                },
            )
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    /// Returns all unconfirmed fee payer transactions for a try-to-send tx.
    /// Transactions whose replacements are confirmed are not included. But if none of the replacements are confirmed, all replacements are returned.
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
        tx: Option<DatabaseTransaction<'_>>,
        bumped_id: u32,
    ) -> Result<Vec<(u32, Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB, i32, i64)>(
            "
            SELECT fpu.id, fpu.fee_payer_txid, fpu.vout, fpu.amount
            FROM tx_sender_fee_payer_utxos fpu
            WHERE fpu.bumped_id = $1
              AND fpu.seen_block_id IS NULL
              AND fpu.is_evicted = false
              AND NOT EXISTS (
                  SELECT 1
                  FROM tx_sender_fee_payer_utxos x
                  WHERE (x.replacement_of_id = fpu.replacement_of_id OR x.id = fpu.replacement_of_id)
                    AND x.seen_block_id IS NOT NULL
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

    /// Marks a fee payer utxo and all its replacements as evicted.
    /// If it is marked as evicted, it will not be tried to be bumped again. (Because wallet can use same utxos for other txs)
    pub async fn mark_fee_payer_utxo_as_evicted(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        id: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_fee_payer_utxos 
                SET is_evicted = true 
                WHERE id = $1 
                OR replacement_of_id = $1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
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

    /// Returns the id of the tx in `tx_sender_try_to_send_txs` if it exists.
    /// Used to avoid adding duplicate transactions to the txsender.
    pub async fn check_if_tx_exists_on_txsender(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        txid: Txid,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_as::<_, (i32,)>(
            "SELECT id FROM tx_sender_try_to_send_txs WHERE txid = $1 LIMIT 1",
        )
        .bind(TxidDB(txid));

        let result: Option<(i32,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(match result {
            Some((id,)) => Some(u32::try_from(id).wrap_err("Failed to convert id to u32")?),
            None => None,
        })
    }

    pub async fn save_tx(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
    /// - Fee rate is lower than the provided maximum fee rate (previous sends had a lower fee rate) or null (transaction wasn't sent before) OR the transaction was sent before, but the chain height increased since then, and the transaction is still not confirmed (accomplished by calling this fn with u32::MAX fee rate)
    ///
    /// # Parameters
    ///
    /// - `tx`: Optional database transaction
    /// - `fee_rate`: Current fee rate of bitcoin or u32::MAX to retrieve all active txs
    /// - `current_tip_height`: The current tip height of the Bitcoin blockchain
    ///   for checking timelocks
    ///
    /// # Returns
    ///
    /// - [`Vec<u32>`]: A vector of transaction ids (db id) that are sendable.
    pub async fn get_sendable_txs(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
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
            i64::try_from(fee_rate.to_sat_per_kwu())
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

    /// Returns the effective fee rate and the block height when it was set.
    /// Returns (None, None) if no effective fee rate has been set yet.
    pub async fn get_effective_fee_rate(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        id: u32,
    ) -> Result<(Option<FeeRate>, Option<u32>), BridgeError> {
        let query = sqlx::query_as::<_, (Option<i64>, Option<i32>)>(
            "SELECT effective_fee_rate, last_bump_block_height FROM tx_sender_try_to_send_txs WHERE id = $1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((Some(rate), block_height)) => Ok((
                Some(FeeRate::from_sat_per_kwu(
                    u64::try_from(rate).wrap_err("Failed to convert effective fee rate to u64")?,
                )),
                block_height.map(|h| h as u32),
            )),
            Some((None, _)) | None => Ok((None, None)),
        }
    }

    /// Updates the effective fee rate and last bump block height for a transaction.
    ///
    /// This function only updates the row if the fee rate is actually changing (or is NULL).
    /// If the fee rate hasn't changed, the entire update is skipped to preserve the existing
    /// `last_bump_block_height`. This ensures the "stuck for 10 blocks" counter continues from
    /// the last actual fee bump, not from retries with the same fee rate.
    ///
    /// # Parameters
    /// * `tx` - Optional database transaction. If None, uses the connection's transaction.
    /// * `id` - The transaction ID to update.
    /// * `effective_fee_rate` - The new effective fee rate to set, the fee rate we sent the tx with.
    /// * `block_height` - The current block height (only updated if fee rate changes).
    ///
    /// # Returns
    /// Returns `Ok(())` on success, or a `BridgeError` if the update fails.
    pub async fn update_effective_fee_rate(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        id: u32,
        effective_fee_rate: FeeRate,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs 
             SET effective_fee_rate = $1, last_bump_block_height = $2 
             WHERE id = $3 AND (effective_fee_rate IS NULL OR effective_fee_rate != $1)",
        )
        .bind(
            i64::try_from(effective_fee_rate.to_sat_per_kwu())
                .wrap_err("Failed to convert effective fee rate to i64")?,
        )
        .bind(i32::try_from(block_height).wrap_err("Failed to convert block_height to i32")?)
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_try_to_send_tx(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
        tx_id: u32,
        error_message: &str,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_debug_submission_errors (tx_id, error_message) VALUES ($1, $2)",
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?)
        .bind(error_message);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
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
        tx: Option<DatabaseTransaction<'_>>,
        tx_id: u32,
    ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64, bool)>(
            r#"
            SELECT fee_payer_txid, vout, amount, seen_block_id IS NOT NULL as confirmed
            FROM tx_sender_fee_payer_utxos
            WHERE bumped_id = $1
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

        let results: Vec<(TxidDB, i32, i64, bool)> =
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
                    *confirmed,
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }
}

#[async_trait]
impl clementine_tx_sender::TxSenderDatabase for Database {
    type Transaction = sqlx::Transaction<'static, sqlx::Postgres>;
    async fn begin_transaction(
        &self,
    ) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, BridgeError> {
        self.begin_transaction().await
    }

    async fn commit_transaction(
        &self,
        tx: sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<(), BridgeError> {
        tx.commit().await.map_err(Into::into)
    }

    async fn save_tx_debug_submission_error(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        tx_id: u32,
        error_message: &str,
    ) -> Result<(), BridgeError> {
        self.save_tx_debug_submission_error(dbtx, tx_id, error_message)
            .await
    }

    async fn get_sendable_txs(
        &self,
        fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<Vec<u32>, BridgeError> {
        self.get_sendable_txs(None, fee_rate, current_tip_height)
            .await
    }

    async fn get_try_to_send_tx(
        &self,
        tx: Option<&mut Self::Transaction>,
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
        self.get_try_to_send_tx(tx, id).await
    }

    async fn update_tx_debug_sending_state(
        &self,
        tx_id: u32,
        state: &str,
        activated: bool,
    ) -> Result<(), BridgeError> {
        self.update_tx_debug_sending_state(tx_id, state, activated)
            .await
    }

    async fn get_all_unconfirmed_fee_payer_txs(
        &self,
        tx: Option<&mut Self::Transaction>,
    ) -> Result<Vec<(u32, u32, Txid, u32, Amount, Option<u32>)>, BridgeError> {
        self.get_all_unconfirmed_fee_payer_txs(tx).await
    }

    async fn get_unconfirmed_fee_payer_txs(
        &self,
        tx: Option<&mut Self::Transaction>,
        bumped_id: u32,
    ) -> Result<Vec<(u32, Txid, u32, Amount)>, BridgeError> {
        self.get_unconfirmed_fee_payer_txs(tx, bumped_id).await
    }

    async fn mark_fee_payer_utxo_as_evicted(
        &self,
        tx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<(), BridgeError> {
        self.mark_fee_payer_utxo_as_evicted(tx, id).await
    }

    async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        self.get_confirmed_fee_payer_utxos(tx, id).await
    }

    async fn save_fee_payer_tx(
        &self,
        tx: Option<&mut Self::Transaction>,
        _try_to_send_id: Option<u32>,
        bumped_id: u32,
        fee_payer_txid: Txid,
        vout: u32,
        amount: Amount,
        replacement_of_id: Option<u32>,
    ) -> Result<(), BridgeError> {
        self.save_fee_payer_tx(
            tx,
            bumped_id,
            fee_payer_txid,
            vout,
            amount,
            replacement_of_id,
        )
        .await
    }

    async fn get_last_rbf_txid(
        &self,
        tx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Option<Txid>, BridgeError> {
        self.get_last_rbf_txid(tx, id).await
    }

    async fn save_rbf_txid(
        &self,
        tx: Option<&mut Self::Transaction>,
        id: u32,
        txid: Txid,
    ) -> Result<(), BridgeError> {
        self.save_rbf_txid(tx, id, txid).await
    }

    async fn save_cancelled_outpoint(
        &self,
        tx: Option<&mut Self::Transaction>,
        cancelled_id: u32,
        outpoint: bitcoin::OutPoint,
    ) -> Result<(), BridgeError> {
        self.save_cancelled_outpoint(tx, cancelled_id, outpoint)
            .await
    }

    async fn save_cancelled_txid(
        &self,
        tx: Option<&mut Self::Transaction>,
        cancelled_id: u32,
        txid: bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        self.save_cancelled_txid(tx, cancelled_id, txid).await
    }

    async fn save_activated_txid(
        &self,
        tx: Option<&mut Self::Transaction>,
        activated_id: u32,
        prerequisite_tx: &ActivatedWithTxid,
    ) -> Result<(), BridgeError> {
        self.save_activated_txid(tx, activated_id, prerequisite_tx)
            .await
    }

    async fn save_activated_outpoint(
        &self,
        tx: Option<&mut Self::Transaction>,
        activated_id: u32,
        activated_outpoint: &ActivatedWithOutpoint,
    ) -> Result<(), BridgeError> {
        self.save_activated_outpoint(tx, activated_id, activated_outpoint)
            .await
    }

    async fn get_effective_fee_rate(
        &self,
        tx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<(Option<FeeRate>, Option<u32>), BridgeError> {
        self.get_effective_fee_rate(tx, id).await
    }

    async fn update_effective_fee_rate(
        &self,
        tx: Option<&mut Self::Transaction>,
        id: u32,
        effective_fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<(), BridgeError> {
        self.update_effective_fee_rate(tx, id, effective_fee_rate, current_tip_height)
            .await
    }

    async fn check_if_tx_exists_on_txsender(
        &self,
        tx: Option<&mut Self::Transaction>,
        txid: Txid,
    ) -> Result<Option<u32>, BridgeError> {
        self.check_if_tx_exists_on_txsender(tx, txid).await
    }

    async fn save_tx(
        &self,
        tx: Option<&mut Self::Transaction>,
        tx_metadata: Option<TxMetadata>,
        raw_tx: &Transaction,
        fee_paying_type: FeePayingType,
        txid: Txid,
        rbf_signing_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError> {
        self.save_tx(
            tx,
            tx_metadata,
            raw_tx,
            fee_paying_type,
            txid,
            rbf_signing_info,
        )
        .await
    }

    async fn get_tx_debug_info(
        &self,
        tx: Option<&mut Self::Transaction>,
        tx_id: u32,
    ) -> Result<Option<String>, BridgeError> {
        self.get_tx_debug_info(tx, tx_id).await
    }

    async fn get_tx_debug_submission_errors(
        &self,
        tx: Option<&mut Self::Transaction>,
        tx_id: u32,
    ) -> Result<Vec<(String, String)>, BridgeError> {
        self.get_tx_debug_submission_errors(tx, tx_id).await
    }

    async fn get_tx_debug_fee_payer_utxos(
        &self,
        tx: Option<&mut Self::Transaction>,
        tx_id: u32,
    ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError> {
        self.get_tx_debug_fee_payer_utxos(tx, tx_id).await
    }

    async fn debug_inactive_txs(&self, fee_rate: FeeRate, current_tip_height: u32) {
        self.debug_inactive_txs(fee_rate, current_tip_height).await
    }

    async fn sync_transaction_confirmations(
        &self,
        tx: Option<&mut Self::Transaction>,
    ) -> Result<(), BridgeError> {
        self.sync_transaction_confirmations(tx).await
    }

    async fn get_max_height(
        &self,
        tx: Option<&mut Self::Transaction>,
    ) -> Result<Option<u32>, BridgeError> {
        self.get_max_height(tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use crate::test::common::*;
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
            annex: None,
            additional_taproot_output_count: None,
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
    async fn test_sync_transaction_confirmations() {
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
        db.insert_txid_to_block(&mut dbtx, block_id, &fee_payer_txid)
            .await
            .unwrap();

        // Sync transaction confirmations
        db.sync_transaction_confirmations(Some(&mut dbtx))
            .await
            .unwrap();

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
        db.update_effective_fee_rate(Some(&mut dbtx), id1, fee_rate, 100)
            .await
            .unwrap();

        let sendable_txs = db
            .get_sendable_txs(Some(&mut dbtx), fee_rate, current_tip_height)
            .await
            .unwrap();
        assert_eq!(sendable_txs.len(), 1);
        assert!(sendable_txs.contains(&id2));

        // increase fee rate, all should be sendable again
        let sendable_txs = db
            .get_sendable_txs(
                Some(&mut dbtx),
                FeeRate::from_sat_per_vb(4).unwrap(),
                current_tip_height + 1,
            )
            .await
            .unwrap();
        assert_eq!(sendable_txs.len(), 2);
        assert!(sendable_txs.contains(&id1));
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
        db.save_tx_debug_submission_error(Some(&mut dbtx), tx_id, error_message)
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
        db.save_tx_debug_submission_error(Some(&mut dbtx), tx_id, second_error)
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
