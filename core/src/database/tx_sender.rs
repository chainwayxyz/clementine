//! # Transaction Sender Related Database Operations
//!
//! This module includes database functions which are mainly used by the transaction sender.

use super::{wrapper::TxidDB, Database, DatabaseTransaction};
use crate::{
    errors::BridgeError,
    execute_query_with_tx,
    tx_sender::{FeePayingType, PrerequisiteTx},
};
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, FeeRate, Transaction, Txid,
};
use std::ops::DerefMut; // Add this at the top with other imports

impl Database {
    pub async fn confirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: i32,
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

        // Update tx_sender_activate_prerequisite_txs
        sqlx::query(&format!(
            "{} 
            UPDATE tx_sender_activate_prerequisite_txs AS tap
            SET seen_block_id = $1
            WHERE tap.txid IN (SELECT txid FROM relevant_txs)
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

        Ok(())
    }

    pub async fn unconfirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: i32,
    ) -> Result<(), BridgeError> {
        // Unconfirm tx_sender_fee_payer_utxos
        sqlx::query(
            r#"
            -- Update tx_sender_activate_prerequisite_txs
            UPDATE tx_sender_activate_prerequisite_txs AS tap
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
        bumped_id: i32,
        fee_payer_txid: Txid,
        vout: u32,
        amount: Amount,
        replacement_of_id: Option<i32>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_fee_payer_utxos (bumped_id, fee_payer_txid, vout, amount, replacement_of_id) 
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(bumped_id)
        .bind(TxidDB(fee_payer_txid))
        .bind(vout as i32)
        .bind(amount.to_sat() as i64)
        .bind(replacement_of_id);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Some fee payer txs may not hit onchain, so we need to bump fees of them.
    /// These txs should not be confirmed and should not be replaced by other txs.
    /// Replaced means that the tx was bumped and the replacement tx is in the database.
    pub async fn get_bumpable_fee_payer_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        bumped_id: i32,
    ) -> Result<Vec<(i32, Txid, u32, Amount)>, BridgeError> {
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
        .bind(bumped_id);

        let results: Vec<(i32, TxidDB, i32, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .iter()
            .map(|(id, fee_payer_txid, vout, amount)| {
                (
                    *id,
                    fee_payer_txid.0,
                    *vout as u32,
                    Amount::from_sat(*amount as u64),
                )
            })
            .collect())
    }

    pub async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: i32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64)>(
            "SELECT fee_payer_txid, vout, amount 
             FROM tx_sender_fee_payer_utxos fpu
             WHERE fpu.bumped_id = $1 AND fpu.seen_block_id IS NOT NULL",
        )
        .bind(id);

        let results: Vec<(TxidDB, i32, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .iter()
            .map(|(fee_payer_txid, vout, amount)| {
                (
                    fee_payer_txid.0,
                    *vout as u32,
                    Amount::from_sat(*amount as u64),
                )
            })
            .collect())
    }

    pub async fn get_unconfirmed_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: i32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64)>(
            "SELECT fee_payer_txid, vout, amount 
             FROM tx_sender_fee_payer_utxos fpu
             WHERE fpu.bumped_id = $1 AND fpu.seen_block_id IS NULL",
        )
        .bind(id);

        let results: Vec<(TxidDB, i32, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .iter()
            .map(|(fee_payer_txid, vout, amount)| {
                (
                    fee_payer_txid.0,
                    *vout as u32,
                    Amount::from_sat(*amount as u64),
                )
            })
            .collect())
    }

    pub async fn save_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        raw_tx: &Transaction,
        fee_paying_type: FeePayingType,
    ) -> Result<i32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO tx_sender_try_to_send_txs (raw_tx, fee_paying_type) VALUES ($1, $2::fee_paying_type) RETURNING id"
        )
        .bind(serialize(raw_tx))
        .bind(fee_paying_type);

        let id: i32 = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok(id)
    }

    pub async fn save_rbf_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: i32,
        txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO tx_sender_rbf_txids (id, txid) VALUES ($1, $2)")
            .bind(id)
            .bind(TxidDB(txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn save_cancelled_outpoint(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        cancelled_id: i32,
        outpoint: bitcoin::OutPoint,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_cancel_try_to_send_outpoints (cancelled_id, txid, vout) VALUES ($1, $2, $3)"
        )
        .bind(cancelled_id)
        .bind(TxidDB(outpoint.txid))
        .bind(outpoint.vout as i32);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn save_cancelled_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        cancelled_id: i32,
        txid: bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_cancel_try_to_send_txids (cancelled_id, txid) VALUES ($1, $2)",
        )
        .bind(cancelled_id)
        .bind(TxidDB(txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn save_activated_prerequisite_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        activated_id: i32,
        prerequisite_tx: &PrerequisiteTx,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_activate_prerequisite_txs (activated_id, txid, timelock) VALUES ($1, $2, $3)"
        )
        .bind(activated_id)
        .bind(TxidDB(prerequisite_tx.txid))
        .bind(prerequisite_tx.timelock.0 as i64);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_sendable_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        fee_rate: FeeRate,
        current_tip_height: u64,
    ) -> Result<Vec<i32>, BridgeError> {
        let select_query = sqlx::query_as::<_, (i32,)>(
            "WITH valid_activated_txs AS (
                    -- Select all tx_sender_try_to_send_txs IDs
                    SELECT txs.id AS activated_id
                    FROM tx_sender_try_to_send_txs AS txs
                    LEFT JOIN tx_sender_activate_prerequisite_txs AS activate
                        ON txs.id = activate.activated_id
                    LEFT JOIN bitcoin_syncer AS syncer
                        ON activate.seen_block_id = syncer.id
                    GROUP BY txs.id
                    HAVING 
                        -- If the transaction has prerequisites, ensure all are activated
                        COUNT(activate.txid) = 0 
                        OR COUNT(activate.txid) = COUNT(CASE WHEN (syncer.height + activate.timelock) <= $2 THEN 1 END)
                ),
                valid_cancel_outpoints AS (
                    SELECT cancelled_id
                    FROM tx_sender_cancel_try_to_send_outpoints
                    WHERE seen_block_id IS NOT NULL
                ),
                valid_cancel_txids AS (
                    SELECT cancelled_id
                    FROM tx_sender_cancel_try_to_send_txids
                    WHERE seen_block_id IS NOT NULL
                )
                SELECT txs.id
                FROM tx_sender_try_to_send_txs AS txs
                WHERE
                    txs.id IN (SELECT activated_id FROM valid_activated_txs)
                    AND txs.id NOT IN (SELECT cancelled_id FROM valid_cancel_outpoints)
                    AND txs.id NOT IN (SELECT cancelled_id FROM valid_cancel_txids)
                    AND (txs.effective_fee_rate IS NULL OR txs.effective_fee_rate <= $1);",
        )
        .bind(fee_rate.to_sat_per_vb_ceil() as i64)
        .bind(current_tip_height as i64);

        let results = execute_query_with_tx!(self.connection, tx, select_query, fetch_all)?;

        let txs = results
            .into_iter()
            .map(|(id,)| Ok(id))
            .collect::<Result<Vec<_>, BridgeError>>()?;

        Ok(txs)
    }

    pub async fn update_effective_fee_rate(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: i32,
        effective_fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_try_to_send_txs SET effective_fee_rate = $1 WHERE id = $2",
        )
        .bind(effective_fee_rate.to_sat_per_vb_ceil() as i64)
        .bind(id);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: i32,
    ) -> Result<(Transaction, FeePayingType, Option<i32>), BridgeError> {
        let query = sqlx::query_as::<_, (Vec<u8>, FeePayingType, Option<i32>)>(
            "SELECT raw_tx, fee_paying_type::fee_paying_type, seen_block_id
             FROM tx_sender_try_to_send_txs 
             WHERE id = $1 LIMIT 1",
        )
        .bind(id);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok((
            deserialize(&result.0)
                .map_err(|e| BridgeError::Error(format!("Bitcoin deserialization error: {}", e)))?,
            result.1,
            result.2,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use crate::{create_test_config_with_thread_name, database::Database};
    use bitcoin::absolute::Height;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Block, OutPoint, Txid};

    async fn setup_test_db() -> Database {
        let config = create_test_config_with_thread_name!(None);
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
        let id = db.save_tx(None, &tx, FeePayingType::CPFP).await.unwrap();

        // Test retrieving tx
        let (retrieved_tx, fee_paying_type, seen_block_id) = db.get_tx(None, id).await.unwrap();
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
            .save_tx(Some(&mut dbtx), &tx, FeePayingType::CPFP)
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

        // Test getting unconfirmed UTXOs
        let unconfirmed = db
            .get_unconfirmed_fee_payer_utxos(Some(&mut dbtx), tx_id)
            .await
            .unwrap();
        assert_eq!(unconfirmed.len(), 1);

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
            .save_tx(Some(&mut dbtx), &tx, FeePayingType::CPFP)
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
        db.confirm_transactions(&mut dbtx, block_id as i32)
            .await
            .unwrap();

        // Verify confirmation
        let unconfirmed = db
            .get_unconfirmed_fee_payer_utxos(Some(&mut dbtx), tx_id)
            .await
            .unwrap();
        assert!(unconfirmed.is_empty());

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
            .save_tx(Some(&mut dbtx), &tx, FeePayingType::CPFP)
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
            .save_tx(Some(&mut dbtx), &tx1, FeePayingType::CPFP)
            .await
            .unwrap();
        let id2 = db
            .save_tx(Some(&mut dbtx), &tx2, FeePayingType::RBF)
            .await
            .unwrap();

        // Test getting sendable txs
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
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
        // This should still make tx1 sendable since the condition is "effective_fee_rate <= fee_rate"
        db.update_effective_fee_rate(Some(&mut dbtx), id1, fee_rate)
            .await
            .unwrap();

        let sendable_txs = db
            .get_sendable_txs(Some(&mut dbtx), fee_rate, current_tip_height)
            .await
            .unwrap();
        assert_eq!(sendable_txs.len(), 2);
        assert!(sendable_txs.contains(&id1));
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
