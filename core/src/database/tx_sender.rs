//! # Transaction Sender Related Database Operations
//!
//! This module includes database functions which are mainly used by the transaction sender.

use super::{wrapper::TxidDB, Database, DatabaseTransaction};
use crate::{
    errors::BridgeError,
    execute_query_with_tx,
    tx_sender::{ActivatedWithOutpoint, ActivatedWithTxid, FeePayingType, TxMetadata},
};
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, FeeRate, Transaction, Txid,
};
use eyre::{Context, OptionExt};
use std::ops::DerefMut;
// Add this at the top with other imports

impl Database {
    pub async fn confirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
    ) -> Result<(), BridgeError> {
        // Common CTEs for reuse
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
        .execute(tx.deref_mut())
        .await?;

        Ok(())
    }

    pub async fn unconfirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
    ) -> Result<(), BridgeError> {
        // Unconfirm tx_sender_fee_payer_utxos
        sqlx::query(
            r#"
            -- Update tx_sender_activate_try_to_send_txids
            UPDATE tx_sender_activate_try_to_send_txids AS tap
            SET seen_block_id = NULL
            WHERE tap.seen_block_id = $1;

            -- Update tx_sender_activate_try_to_send_outpoints
            UPDATE tx_sender_activate_try_to_send_outpoints AS tap
            SET seen_block_id = NULL
            WHERE tap.seen_block_id = $1;

            -- Update tx_sender_cancel_try_to_send_txids
            UPDATE tx_sender_cancel_try_to_send_txids AS ctt
            SET seen_block_id = NULL
            WHERE ctt.seen_block_id = $1;

            -- Update tx_sender_cancel_try_to_send_outpoints
            UPDATE tx_sender_cancel_try_to_send_outpoints AS cto
            SET seen_block_id = NULL
            WHERE cto.seen_block_id = $1;

            -- Update tx_sender_fee_payer_utxos
            UPDATE tx_sender_fee_payer_utxos AS fpu
            SET seen_block_id = NULL
            WHERE fpu.seen_block_id = $1;

            -- Update tx_sender_try_to_send_txs
            UPDATE tx_sender_try_to_send_txs AS txs
            SET seen_block_id = NULL
            WHERE txs.seen_block_id = $1;
            "#,
        )
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?)
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

    /// Some fee payer txs may not hit onchain, so we need to bump fees of them.
    /// These txs should not be confirmed and should not be replaced by other txs.
    /// Replaced means that the tx was bumped and the replacement tx is in the database.
    pub async fn get_bumpable_fee_payer_txs(
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
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO tx_sender_try_to_send_txs (raw_tx, fee_paying_type, tx_metadata, txid) VALUES ($1, $2::fee_paying_type, $3, $4) RETURNING id"
        )
        .bind(serialize(raw_tx))
        .bind(fee_paying_type)
        .bind(serde_json::to_string(&tx_metadata).wrap_err("Failed to encode tx_metadata to JSON")?)
        .bind(TxidDB(txid));

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

                    -- Transactions with outpoint activations that aren't active yet
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
                    -- Transactions with cancelled outpoints
                    SELECT DISTINCT
                        cancelled_id AS tx_id
                    FROM
                        tx_sender_cancel_try_to_send_outpoints
                    WHERE
                        seen_block_id IS NOT NULL

                    UNION

                    -- Transactions with cancelled txids
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

    pub async fn get_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: u32,
    ) -> Result<(Option<TxMetadata>, Transaction, FeePayingType, Option<u32>), BridgeError> {
        let query =
            sqlx::query_as::<_, (Option<String>, Option<Vec<u8>>, FeePayingType, Option<i32>)>(
                "SELECT tx_metadata, raw_tx, fee_paying_type, seen_block_id
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
        ))
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
    use bitcoin::{Block, OutPoint, Txid};

    async fn setup_test_db() -> Database {
        let config = create_test_config_with_thread_name(None).await;
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
        let id = db
            .save_tx(None, None, &tx, FeePayingType::CPFP, txid)
            .await
            .unwrap();

        // Test retrieving tx
        let (_, retrieved_tx, fee_paying_type, seen_block_id) = db.get_tx(None, id).await.unwrap();
        assert_eq!(tx.version, retrieved_tx.version);
        assert_eq!(fee_paying_type, FeePayingType::CPFP);
        assert_eq!(seen_block_id, None);
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
}
