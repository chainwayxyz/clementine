//! SQLx queries for tx-sender tables.

use super::wrapper::TxidDB;
use super::{TxSenderDb, TxSenderDbTx};
use crate::txsender_execute_query_with_tx;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Amount, Transaction, Txid};
use clementine_errors::BridgeError;
use clementine_primitives::FeeRateKvb;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::{Context, OptionExt};
use sqlx::Executor;
use std::collections::HashMap;

use crate::ActivatedWithTxid;

impl TxSenderDb {
    /// Saves a fee payer transaction to the database.
    ///
    /// # Arguments
    /// * `bumped_id` - The id of the transaction funded by this fee payer.
    /// * `fee_payer_txid` - The txid of the fee payer transaction.
    /// * `vout` - The output index of the fee payer UTXO.
    /// * `amount` - The amount in satoshis.
    /// * `replacement_of_id` - The fee payer UTXO this row replaces, if any.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_fee_payer_tx(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
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
        .bind(
            replacement_of_id
                .map(i32::try_from)
                .transpose()
                .wrap_err("Failed to convert replacement of id to i32")?,
        );

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Returns all unconfirmed fee payer UTXOs.
    ///
    /// UTXOs whose replacement chain already has a confirmed member are excluded. If no
    /// replacement in the chain is confirmed, all unconfirmed replacements are returned.
    ///
    /// # Returns
    ///
    /// A vector of fee payer UTXO details:
    /// - [`u32`]: id of the fee payer UTXO row.
    /// - [`u32`]: id of the bumped transaction.
    /// - [`Txid`]: txid of the fee payer transaction.
    /// - [`u32`]: output index of the UTXO.
    /// - [`Amount`]: amount in satoshis.
    /// - [`Option<u32>`]: replaced fee payer UTXO id, if this is a replacement.
    pub async fn get_all_unconfirmed_fee_payer_txs(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<(u32, u32, Txid, u32, Amount, Option<u32>)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, i32, TxidDB, i32, i64, Option<i32>)>(
            "
            SELECT fpu.id, fpu.bumped_id, fpu.fee_payer_txid, fpu.vout, fpu.amount, fpu.replacement_of_id
            FROM tx_sender_fee_payer_utxos fpu
            WHERE fpu.seen_at_height IS NULL
              AND fpu.is_evicted = false
              AND NOT EXISTS (
                  SELECT 1
                  FROM tx_sender_fee_payer_utxos x
                  WHERE COALESCE(x.replacement_of_id, x.id)
                        = COALESCE(fpu.replacement_of_id, fpu.id)
                    AND x.seen_at_height IS NOT NULL
              )
            ",
        );

        let results: Vec<(i32, i32, TxidDB, i32, i64, Option<i32>)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

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

    /// Returns unconfirmed fee payer UTXOs for one try-to-send transaction.
    ///
    /// UTXOs whose replacement chain already has a confirmed member are excluded. If no
    /// replacement in the chain is confirmed, all unconfirmed replacements are returned.
    ///
    /// # Arguments
    /// * `bumped_id` - The id of the transaction funded by the fee payer UTXOs.
    ///
    /// # Returns
    ///
    /// A vector of fee payer UTXO details:
    /// - [`u32`]: id of the fee payer UTXO row.
    /// - [`Txid`]: txid of the fee payer transaction.
    /// - [`u32`]: output index of the UTXO.
    /// - [`Amount`]: amount in satoshis.
    pub async fn get_unconfirmed_fee_payer_txs(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        bumped_id: u32,
    ) -> Result<Vec<(u32, Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB, i32, i64)>(
            "
            SELECT fpu.id, fpu.fee_payer_txid, fpu.vout, fpu.amount
            FROM tx_sender_fee_payer_utxos fpu
            WHERE fpu.bumped_id = $1
              AND fpu.seen_at_height IS NULL
              AND fpu.is_evicted = false
              AND NOT EXISTS (
                  SELECT 1
                  FROM tx_sender_fee_payer_utxos x
                  WHERE COALESCE(x.replacement_of_id, x.id)
                        = COALESCE(fpu.replacement_of_id, fpu.id)
                    AND x.seen_at_height IS NOT NULL
              )
            ",
        )
        .bind(i32::try_from(bumped_id).wrap_err("Failed to convert bumped id to i32")?);

        let results: Vec<(i32, TxidDB, i32, i64)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

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

    /// Marks a fee payer UTXO and all of its replacements as evicted.
    ///
    /// Evicted fee payer UTXOs are no longer selected for bumps, because their wallet
    /// inputs may already have been reused elsewhere.
    pub async fn mark_fee_payer_utxo_as_evicted(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_fee_payer_utxos
                SET is_evicted = true
                WHERE id = $1
                OR replacement_of_id = $1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64)>(
            "SELECT fee_payer_txid, vout, amount
             FROM tx_sender_fee_payer_utxos fpu
             WHERE fpu.bumped_id = $1 AND fpu.seen_at_height IS NOT NULL",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let results: Vec<(TxidDB, i32, i64)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

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

    /// Returns the tx-sender row id for `txid` if it already exists.
    ///
    /// This is used before inserting to avoid adding duplicate transactions to the queue.
    pub async fn check_if_tx_exists_on_txsender(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        txid: Txid,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_as::<_, (i32,)>(
            "SELECT id FROM tx_sender_try_to_send_txs WHERE txid = $1 LIMIT 1",
        )
        .bind(TxidDB(txid));

        let result: Option<(i32,)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_optional)?;

        Ok(match result {
            Some((id,)) => Some(u32::try_from(id).wrap_err("Failed to convert id to u32")?),
            None => None,
        })
    }

    pub async fn save_tx(
        &self,
        tx: TxSenderDbTx<'_>,
        tx_metadata: Option<TxMetadata>,
        raw_tx: &Transaction,
        fee_paying_type: FeePayingType,
        txid: Txid,
        rbf_signing_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_scalar(
            r#"
            INSERT INTO tx_sender_try_to_send_txs
            (raw_tx, fee_paying_type, tx_metadata, txid, rbf_signing_info)
            VALUES ($1, $2::fee_paying_type, $3, $4, $5)
            ON CONFLICT (txid)
            DO UPDATE SET txid = EXCLUDED.txid
            RETURNING id
            "#,
        )
        .bind(serialize(raw_tx))
        .bind(fee_paying_type)
        .bind(serde_json::to_string(&tx_metadata).wrap_err("Failed to encode tx_metadata to JSON")?)
        .bind(TxidDB(txid))
        .bind(
            serde_json::to_string(&rbf_signing_info)
                .wrap_err("Failed to encode rbf_signing_info to JSON")?,
        );

        let id: i32 = query.fetch_one(&mut **tx).await?;
        u32::try_from(id)
            .wrap_err("Failed to convert id to u32")
            .map_err(Into::into)
    }

    pub async fn save_rbf_txid(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
        txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_rbf_txids (id, txid) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?)
        .bind(TxidDB(txid));

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_last_rbf_txid(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<Option<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB,)>(
            "SELECT txid FROM tx_sender_rbf_txids WHERE id = $1 ORDER BY insertion_order DESC LIMIT 1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let result: Option<(TxidDB,)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_optional)?;
        Ok(result.map(|(txid,)| txid.0))
    }

    pub async fn list_rbf_txids_for_id(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<Vec<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB,)>(
            "SELECT txid FROM tx_sender_rbf_txids WHERE id = $1 ORDER BY insertion_order DESC",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let results: Vec<(TxidDB,)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        Ok(results.into_iter().map(|(txid,)| txid.0).collect())
    }

    pub async fn save_activated_txid(
        &self,
        tx: TxSenderDbTx<'_>,
        activated_id: u32,
        prerequisite_tx: &ActivatedWithTxid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_activate_try_to_send_txids (activated_id, txid, timelock) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(i32::try_from(activated_id).wrap_err("Failed to convert activated id to i32")?)
        .bind(TxidDB(prerequisite_tx.txid))
        .bind(i32::try_from(prerequisite_tx.relative_block_height).wrap_err("Failed to convert relative block height to i32")?);

        query.execute(&mut **tx).await?;
        Ok(())
    }

    /// Returns unconfirmed try-to-send transactions that satisfy all queue conditions.
    ///
    /// A transaction is sendable when:
    /// - all activation dependencies have been seen and their relative block timelocks passed;
    /// - zero-timelock txid activations are either seen on-chain or currently in mempool;
    /// - the transaction itself has not been seen on-chain;
    /// - its inputs have not exceeded the unavailable-input retry limit;
    /// - its previous effective fee rate is lower than `fee_rate`, or it has never been sent.
    ///
    /// Passing a very high `fee_rate` is used by callers to retrieve all active transactions
    /// after a new block, even when the market fee did not increase.
    ///
    /// # Returns
    ///
    /// A vector of tx-sender database ids that are ready to send or bump.
    pub async fn get_sendable_txs(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        fee_rate: FeeRateKvb,
        current_tip_height: u32,
    ) -> Result<Vec<u32>, BridgeError> {
        let select_query = sqlx::query_as::<_, (i32,)>(
            "WITH
                non_active_txs AS (
                    SELECT DISTINCT
                        activate_txid.activated_id AS tx_id
                    FROM
                        tx_sender_activate_try_to_send_txids AS activate_txid
                    WHERE
                        (
                            activate_txid.timelock > 0
                            AND (
                                activate_txid.seen_at_height IS NULL
                                OR (activate_txid.seen_at_height::bigint + activate_txid.timelock > $2::bigint)
                            )
                        )
                        OR (
                            activate_txid.timelock = 0
                            AND activate_txid.seen_at_height IS NULL
                            AND activate_txid.in_mempool IS NOT TRUE
                        )
                )

                SELECT
                    txs.id
                FROM
                    tx_sender_try_to_send_txs AS txs
                WHERE
                    txs.id NOT IN (SELECT tx_id FROM non_active_txs)
                    AND txs.seen_at_height IS NULL
                    AND txs.input_unspent_timed_out = FALSE
                    AND (
                        txs.fee_paying_type = 'cpfp'::fee_paying_type
                        OR txs.effective_fee_rate IS NULL
                        OR txs.effective_fee_rate < $1
                    );",
        )
        .bind(
            i64::try_from(fee_rate.to_sat_per_kvb()).wrap_err("Failed to convert fee rate to i64")?,
        )
        .bind(i32::try_from(current_tip_height).wrap_err("Failed to convert current tip height to i32")?);

        let results = txsender_execute_query_with_tx!(&self.pool, tx, select_query, fetch_all)?;

        let txs = results
            .into_iter()
            .map(|(id,)| u32::try_from(id))
            .collect::<Result<Vec<_>, _>>()
            .wrap_err("Failed to convert id to u32")?;

        Ok(txs)
    }

    /// Increments the consecutive "inputs unavailable" counter for the tx and
    /// marks it timed out once the configured retry limit is reached.
    ///
    /// Returns whether the tx is now timed out.
    pub async fn mark_input_unspent_check_failed(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
        max_retries: u32,
    ) -> Result<bool, BridgeError> {
        let query = sqlx::query_as::<_, (bool,)>(
            r#"
            UPDATE tx_sender_try_to_send_txs
            SET
                input_unspent_failures = input_unspent_failures + 1,
                input_unspent_timed_out = (
                    input_unspent_timed_out
                    OR (input_unspent_failures + 1 >= $2)
                )
            WHERE id = $1
            RETURNING input_unspent_timed_out
            "#,
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?)
        .bind(i32::try_from(max_retries).wrap_err("Failed to convert max_retries to i32")?);

        let (timed_out,) = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_one)?;
        Ok(timed_out)
    }

    /// Resets the consecutive "inputs unavailable" counter after a successful
    /// input-unspent check.
    pub async fn clear_input_unspent_check_failures(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs
             SET input_unspent_failures = 0
             WHERE id = $1 AND input_unspent_timed_out = FALSE AND input_unspent_failures > 0",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Returns the effective fee rate and block height from the last actual fee bump.
    ///
    /// Returns `(None, None)` if no effective fee rate has been recorded yet.
    pub async fn get_effective_fee_rate(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<(Option<FeeRateKvb>, Option<u32>), BridgeError> {
        let query = sqlx::query_as::<_, (Option<i64>, Option<i32>)>(
            "SELECT effective_fee_rate, last_bump_block_height FROM tx_sender_try_to_send_txs WHERE id = $1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let result = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_optional)?;

        match result {
            Some((Some(rate), block_height)) => Ok((
                Some(FeeRateKvb::from_sat_per_kvb(
                    u64::try_from(rate).wrap_err("Failed to convert effective fee rate to u64")?,
                )),
                block_height.map(|h| h as u32),
            )),
            Some((None, _)) | None => Ok((None, None)),
        }
    }

    /// Updates the effective fee rate and last bump block height for a transaction.
    ///
    /// The row is updated only when the fee rate changes, or when the previous fee rate
    /// is `NULL`. This preserves `last_bump_block_height` across retries at the same
    /// fee rate, so the stuck-for-N-blocks counter continues from the last real bump.
    ///
    /// `effective_fee_rate` is stored in sat/kvB.
    pub async fn update_effective_fee_rate(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
        effective_fee_rate: FeeRateKvb,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs
             SET effective_fee_rate = $1, last_bump_block_height = $2
             WHERE id = $3 AND (effective_fee_rate IS NULL OR effective_fee_rate != $1)",
        )
        .bind(
            i64::try_from(effective_fee_rate.to_sat_per_kvb())
                .wrap_err("Failed to convert effective fee rate to i64")?,
        )
        .bind(i32::try_from(block_height).wrap_err("Failed to convert block_height to i32")?)
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_try_to_send_tx(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
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
            "SELECT tx_metadata, raw_tx, fee_paying_type, seen_at_height, rbf_signing_info
             FROM tx_sender_try_to_send_txs
             WHERE id = $1 LIMIT 1",
        )
        .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?);

        let result = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_one)?;
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
                .wrap_err("Failed to convert seen_at_height to u32")?,
            serde_json::from_str(result.4.as_deref().unwrap_or("null")).wrap_err_with(|| {
                format!("Failed to decode rbf_signing_info from {:?}", result.4)
            })?,
        ))
    }

    /// Saves a transaction submission error to the debug table.
    pub async fn save_tx_debug_submission_error(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        tx_id: u32,
        error_message: &str,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_debug_submission_errors (tx_id, error_message) VALUES ($1, $2)",
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?)
        .bind(error_message);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Updates or inserts the transaction's current debug sending state.
    ///
    /// This intentionally does not accept a database transaction. It is debug-only
    /// metadata and callers should use it after the tx-sender row has been committed.
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

        self.pool.execute(query).await?;
        Ok(())
    }

    /// Returns the current debug sending state for a transaction.
    pub async fn get_tx_debug_info(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
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

        let result = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_optional)?;
        match result {
            Some((state,)) => Ok(state),
            None => Ok(None),
        }
    }

    /// Returns all recorded submission errors for a transaction, ordered by timestamp.
    pub async fn get_tx_debug_submission_errors(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
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

        txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all).map_err(Into::into)
    }

    /// Returns all fee payer UTXOs for a transaction with their confirmation status.
    pub async fn get_tx_debug_fee_payer_utxos(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        tx_id: u32,
    ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64, bool)>(
            r#"
            SELECT fee_payer_txid, vout, amount, seen_at_height IS NOT NULL as confirmed
            FROM tx_sender_fee_payer_utxos
            WHERE bumped_id = $1
            "#,
        )
        .bind(i32::try_from(tx_id).wrap_err("Failed to convert tx_id to i32")?);

        let results: Vec<(TxidDB, i32, i64, bool)> =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;

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

    /// Debug-only helper: log why some txs are inactive (not sendable).
    pub async fn debug_inactive_txs(&self, fee_rate: FeeRateKvb, current_tip_height: u32) {
        tracing::info!("TXSENDER_DBG_INACTIVE_TXS: Checking inactive transactions");

        let unconfirmed_txs = match sqlx::query_as::<_, (i32, TxidDB, Option<String>, bool)>(
            "SELECT id, txid, tx_metadata, input_unspent_timed_out FROM tx_sender_try_to_send_txs WHERE seen_at_height IS NULL",
        )
        .fetch_all(&self.pool)
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

        for (tx_id, txid, tx_metadata, input_unspent_timed_out) in unconfirmed_txs {
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
                tx_metadata.as_ref().map(|metadata| metadata.tx_type)
            );

            if input_unspent_timed_out {
                tracing::info!(
                    "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because input-unspent retries timed out",
                    id
                );
                continue;
            }

            // txid activations
            let txid_activations = match sqlx::query_as::<_, (Option<i32>, i64, TxidDB)>(
                "SELECT seen_at_height, timelock, txid
                FROM tx_sender_activate_try_to_send_txids
                WHERE activated_id = $1",
            )
            .bind(tx_id)
            .fetch_all(&self.pool)
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

            for (seen_at_height, timelock, txid) in txid_activations {
                if seen_at_height.is_none() {
                    tracing::info!("TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its txid activation {} has not been seen", id, txid.0);
                    continue;
                }

                let seen_at_height = seen_at_height.expect("checked above");
                if (seen_at_height as i64) + timelock > current_tip_height as i64 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its txid activation timelock hasn't expired (seen_at_height: {}, timelock: {}, current_tip_height: {})",
                        id, seen_at_height, timelock, current_tip_height
                    );
                }
            }

            let effective_fee_rate = match sqlx::query_scalar::<_, Option<i64>>(
                "SELECT effective_fee_rate FROM tx_sender_try_to_send_txs WHERE id = $1",
            )
            .bind(tx_id)
            .fetch_one(&self.pool)
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
                if rate >= fee_rate.to_sat_per_kvb() as i64 {
                    tracing::info!(
                        "TXSENDER_DBG_INACTIVE_TXS: TX {} is inactive because its effective fee rate ({} sat/kvB) is >= the current fee rate ({} sat/kvB)",
                        id,
                        rate,
                        fee_rate.to_sat_per_kvb()
                    );
                }
            }
        }
    }

    /// Lists all unfinalized try-to-send transactions that should be checked for confirmation.
    ///
    /// Transactions whose inputs have repeatedly been unavailable past the configured retry limit
    /// are excluded, because txsender assumes at least one of its inputs were spent in another tx, so it's impossible to send the tx.
    pub async fn list_unfinalized_try_to_send_txs(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<(u32, FeePayingType, Txid, Option<u32>)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, FeePayingType, TxidDB, Option<i32>)>(
            r#"
            SELECT id, fee_paying_type, txid, seen_at_height
            FROM tx_sender_try_to_send_txs
            WHERE is_finalized = FALSE
              AND input_unspent_timed_out = FALSE
            "#,
        );

        let results = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        results
            .into_iter()
            .map(|(id, fee_paying_type, txid, seen_at_height)| {
                Ok((
                    u32::try_from(id).wrap_err("Failed to convert id to u32")?,
                    fee_paying_type,
                    txid.0,
                    seen_at_height
                        .map(u32::try_from)
                        .transpose()
                        .wrap_err("Failed to convert seen_at_height to u32")?,
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn list_rbf_txids_for_ids(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        ids: &[u32],
    ) -> Result<Vec<(u32, Txid)>, BridgeError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }

        let ids_i32: Vec<i32> = ids
            .iter()
            .copied()
            .map(i32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .wrap_err("Failed to convert ids to i32")?;

        let query = sqlx::query_as::<_, (i32, TxidDB)>(
            "SELECT id, txid FROM tx_sender_rbf_txids WHERE id = ANY($1) ORDER BY insertion_order DESC",
        )
        .bind(ids_i32);

        let results = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        results
            .into_iter()
            .map(|(id, txid)| {
                Ok((
                    u32::try_from(id).wrap_err("Failed to convert id to u32")?,
                    txid.0,
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn set_try_to_send_seen_at_height(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
        seen_at_height: Option<u32>,
    ) -> Result<(), BridgeError> {
        let query =
            sqlx::query("UPDATE tx_sender_try_to_send_txs SET seen_at_height = $2 WHERE id = $1")
                .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?)
                .bind(
                    seen_at_height
                        .map(i32::try_from)
                        .transpose()
                        .wrap_err("Failed to convert seen_at_height to i32")?,
                );

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Returns seen_at_height and is_finalized for a set of try_to_send ids.
    pub async fn list_try_to_send_statuses_by_ids(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        ids: &[u32],
    ) -> Result<HashMap<u32, (Option<u32>, bool)>, BridgeError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }

        let ids_i32: Vec<i32> = ids
            .iter()
            .copied()
            .map(i32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .wrap_err("Failed to convert ids to i32")?;

        let query = sqlx::query_as::<_, (i32, Option<i32>, bool)>(
            "SELECT id, seen_at_height, is_finalized
             FROM tx_sender_try_to_send_txs
             WHERE id = ANY($1)",
        )
        .bind(ids_i32);

        let results = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        let mut map = HashMap::with_capacity(results.len());
        for (id, seen_at_height, is_finalized) in results {
            let id = u32::try_from(id).wrap_err("Failed to convert id to u32")?;
            let seen_at_height = seen_at_height
                .map(u32::try_from)
                .transpose()
                .wrap_err("Failed to convert seen_at_height to u32")?;
            map.insert(id, (seen_at_height, is_finalized));
        }

        Ok(map)
    }

    pub async fn set_try_to_send_finalized(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        id: u32,
        is_finalized: bool,
    ) -> Result<(), BridgeError> {
        let query =
            sqlx::query("UPDATE tx_sender_try_to_send_txs SET is_finalized = $2 WHERE id = $1")
                .bind(i32::try_from(id).wrap_err("Failed to convert id to i32")?)
                .bind(is_finalized);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    /// Lists all unfinalized fee payer UTXOs that should be checked for confirmation.
    ///
    /// Fee payer UTXOs form replacement chains via `replacement_of_id`:
    /// - The first created UTXO in a chain has `replacement_of_id IS NULL` and its `id` is
    ///   the canonical parent id for the chain.
    /// - All replacements in that chain have `replacement_of_id = <parent id>`.
    ///
    /// This function excludes fee payer UTXOs where **any** UTXO in the same replacement chain
    /// (canonical parent or any of its replacements) is already finalized. Once a chain has a
    /// finalized fee payer UTXO, there's no need to check the others, preventing unnecessary
    /// RPC calls.
    pub async fn list_unfinalized_fee_payer_utxos(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<(u32, Txid, Option<u32>)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB, Option<i32>)>(
            r#"
            SELECT id, fee_payer_txid, seen_at_height
            FROM tx_sender_fee_payer_utxos
            WHERE is_finalized = FALSE
              AND NOT EXISTS (
                  SELECT 1
                  FROM tx_sender_fee_payer_utxos other
                  WHERE COALESCE(other.replacement_of_id, other.id)
                        = COALESCE(tx_sender_fee_payer_utxos.replacement_of_id, tx_sender_fee_payer_utxos.id)
                    AND other.is_finalized = TRUE
              )
            "#,
        );

        let results = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        results
            .into_iter()
            .map(|(id, txid, seen_at_height)| {
                Ok((
                    u32::try_from(id).wrap_err("Failed to convert id to u32")?,
                    txid.0,
                    seen_at_height
                        .map(u32::try_from)
                        .transpose()
                        .wrap_err("Failed to convert seen_at_height to u32")?,
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn set_fee_payer_seen_at_height(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        fee_payer_utxo_id: u32,
        seen_at_height: Option<u32>,
    ) -> Result<(), BridgeError> {
        let query =
            sqlx::query("UPDATE tx_sender_fee_payer_utxos SET seen_at_height = $2 WHERE id = $1")
                .bind(i32::try_from(fee_payer_utxo_id).wrap_err("Failed to convert id to i32")?)
                .bind(
                    seen_at_height
                        .map(i32::try_from)
                        .transpose()
                        .wrap_err("Failed to convert seen_at_height to i32")?,
                );

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn set_fee_payer_finalized(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        fee_payer_utxo_id: u32,
        is_finalized: bool,
    ) -> Result<(), BridgeError> {
        let query =
            sqlx::query("UPDATE tx_sender_fee_payer_utxos SET is_finalized = $2 WHERE id = $1")
                .bind(i32::try_from(fee_payer_utxo_id).wrap_err("Failed to convert id to i32")?)
                .bind(is_finalized);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn list_unfinalized_activate_txids(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
    ) -> Result<Vec<(u32, Txid, Option<u32>, bool)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB, Option<i32>, bool)>(
            r#"
            SELECT activated_id, txid, seen_at_height, in_mempool
            FROM tx_sender_activate_try_to_send_txids
            WHERE is_finalized = FALSE
            "#,
        );

        let results = txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_all)?;
        results
            .into_iter()
            .map(|(activated_id, txid, seen_at_height, in_mempool)| {
                Ok((
                    u32::try_from(activated_id)
                        .wrap_err("Failed to convert activated_id to u32")?,
                    txid.0,
                    seen_at_height
                        .map(u32::try_from)
                        .transpose()
                        .wrap_err("Failed to convert seen_at_height to u32")?,
                    in_mempool,
                ))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn set_activate_txid_seen_at_height(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        activated_id: u32,
        txid: Txid,
        seen_at_height: Option<u32>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_txids SET seen_at_height = $3 WHERE activated_id = $1 AND txid = $2",
        )
        .bind(i32::try_from(activated_id).wrap_err("Failed to convert activated_id to i32")?)
        .bind(TxidDB(txid))
        .bind(
            seen_at_height
                .map(i32::try_from)
                .transpose()
                .wrap_err("Failed to convert seen_at_height to i32")?,
        );

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn set_activate_txid_finalized(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        activated_id: u32,
        txid: Txid,
        is_finalized: bool,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_txids SET is_finalized = $3 WHERE activated_id = $1 AND txid = $2",
        )
        .bind(i32::try_from(activated_id).wrap_err("Failed to convert activated_id to i32")?)
        .bind(TxidDB(txid))
        .bind(is_finalized);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn set_activate_txid_mempool_status(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        activated_id: u32,
        txid: Txid,
        in_mempool: bool,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_activate_try_to_send_txids SET in_mempool = $3 WHERE activated_id = $1 AND txid = $2",
        )
        .bind(i32::try_from(activated_id).wrap_err("Failed to convert activated_id to i32")?)
        .bind(TxidDB(txid))
        .bind(in_mempool);

        txsender_execute_query_with_tx!(&self.pool, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_activate_txid_status(
        &self,
        tx: Option<TxSenderDbTx<'_>>,
        txid: Txid,
    ) -> Result<Option<(bool, Option<u32>)>, BridgeError> {
        let query = sqlx::query_as::<_, (Option<bool>, Option<i32>)>(
            "SELECT bool_or(in_mempool), max(seen_at_height)
             FROM tx_sender_activate_try_to_send_txids
             WHERE txid = $1",
        )
        .bind(TxidDB(txid));

        let (any_in_mempool, seen_at_height): (Option<bool>, Option<i32>) =
            txsender_execute_query_with_tx!(&self.pool, tx, query, fetch_one)?;

        if any_in_mempool.is_none() && seen_at_height.is_none() {
            return Ok(None);
        }

        let any_in_mempool = any_in_mempool.unwrap_or(false);
        let seen_at_height = seen_at_height
            .map(u32::try_from)
            .transpose()
            .wrap_err("Failed to convert seen_at_height to u32")?;

        Ok(Some((any_in_mempool, seen_at_height)))
    }

    pub async fn delete_try_to_send_tx(
        &self,
        mut tx: Option<TxSenderDbTx<'_>>,
        id: u32,
    ) -> Result<(), BridgeError> {
        let id_i32 = i32::try_from(id).wrap_err("Failed to convert id to i32")?;

        let queries = [
            "DELETE FROM tx_sender_debug_sending_state WHERE tx_id = $1",
            "DELETE FROM tx_sender_debug_submission_errors WHERE tx_id = $1",
            "DELETE FROM tx_sender_rbf_txids WHERE id = $1",
            "DELETE FROM tx_sender_fee_payer_utxos WHERE bumped_id = $1",
            "DELETE FROM tx_sender_activate_try_to_send_txids WHERE activated_id = $1",
            "DELETE FROM tx_sender_try_to_send_txs WHERE id = $1",
        ];

        for sql in queries {
            let query = sqlx::query(sql).bind(id_i32);
            txsender_execute_query_with_tx!(&self.pool, tx.as_deref_mut(), query, execute)?;
        }

        Ok(())
    }

    pub async fn update_synced_height(&self, height: u32) -> Result<(), BridgeError> {
        sqlx::query(
            "INSERT INTO tx_sender_sync_state (id, synced_height, updated_at)
             VALUES (1, $1, NOW())
             ON CONFLICT (id) DO UPDATE SET synced_height = EXCLUDED.synced_height, updated_at = NOW()",
        )
        .bind(i32::try_from(height).wrap_err("Failed to convert height to i32")?)
        .execute(&self.pool)
        .await
        .map_err(BridgeError::DatabaseError)?;
        Ok(())
    }

    pub async fn get_synced_height(&self) -> Result<Option<u32>, BridgeError> {
        let result: Option<i32> =
            sqlx::query_scalar("SELECT synced_height FROM tx_sender_sync_state WHERE id = 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(BridgeError::DatabaseError)?;

        Ok(result
            .map(|h| u32::try_from(h).wrap_err("Failed to convert height from DB"))
            .transpose()?)
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use crate::test_utils::create_test_environment;
    use bitcoin::hashes::Hash as _;
    use bitcoin::transaction::Version;
    use bitcoin::{absolute, Transaction, Txid};

    fn txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn empty_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    async fn save_fee_payer_chain(db: &TxSenderDb, txid_prefix: u8) -> (u32, u32, u32) {
        let mut dbtx = db.begin_transaction().await.unwrap();
        let bumped_id = db
            .save_tx(
                &mut dbtx,
                None,
                &empty_tx(),
                FeePayingType::CPFP,
                txid(txid_prefix),
                None,
            )
            .await
            .unwrap();
        db.commit_transaction(dbtx).await.unwrap();

        let root_txid = txid(txid_prefix + 1);
        db.save_fee_payer_tx(
            None,
            bumped_id,
            root_txid,
            0,
            Amount::from_sat(10_000),
            None,
        )
        .await
        .unwrap();

        let initial: Vec<(u32, u32, Txid, u32, Amount, Option<u32>)> =
            db.get_all_unconfirmed_fee_payer_txs(None).await.unwrap();
        let root_id = initial
            .iter()
            .find_map(|(id, chain_bumped_id, txid, _, _, _)| {
                (*chain_bumped_id == bumped_id && *txid == root_txid).then_some(*id)
            })
            .unwrap();

        let replacement_txid = txid(txid_prefix + 2);
        db.save_fee_payer_tx(
            None,
            bumped_id,
            replacement_txid,
            0,
            Amount::from_sat(10_000),
            Some(root_id),
        )
        .await
        .unwrap();

        let replacement_id: i32 = sqlx::query_scalar(
            "SELECT id FROM tx_sender_fee_payer_utxos WHERE fee_payer_txid = $1",
        )
        .bind(TxidDB(replacement_txid))
        .fetch_one(db.pool())
        .await
        .unwrap();

        let unconfirmed = db
            .get_unconfirmed_fee_payer_txs(None, bumped_id)
            .await
            .unwrap();
        assert_eq!(unconfirmed.len(), 2);

        (bumped_id, root_id, replacement_id as u32)
    }

    async fn assert_no_unconfirmed_fee_payers(db: &TxSenderDb, bumped_id: u32) {
        assert!(db
            .get_unconfirmed_fee_payer_txs(None, bumped_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn confirmed_fee_payer_chain_has_no_unconfirmed_txs() {
        let db = create_test_environment(true, false).await.1.unwrap();

        let (root_confirmed_bumped_id, root_id, _) = save_fee_payer_chain(&db, 10).await;
        db.set_fee_payer_seen_at_height(None, root_id, Some(100))
            .await
            .unwrap();
        assert_no_unconfirmed_fee_payers(&db, root_confirmed_bumped_id).await;

        let (replacement_confirmed_bumped_id, _, replacement_id) =
            save_fee_payer_chain(&db, 20).await;
        db.set_fee_payer_seen_at_height(None, replacement_id, Some(101))
            .await
            .unwrap();
        assert_no_unconfirmed_fee_payers(&db, replacement_confirmed_bumped_id).await;

        assert!(db
            .get_all_unconfirmed_fee_payer_txs(None)
            .await
            .unwrap()
            .is_empty());
    }
}
