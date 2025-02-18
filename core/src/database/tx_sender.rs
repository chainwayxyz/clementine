//! # Transaction Sender Related Database Operations
//!
//! This module includes database functions which are mainly used by the transaction sender.

use super::{
    wrapper::{OutPointDB, TxidDB},
    Database, DatabaseTransaction,
};
use crate::{
    errors::BridgeError,
    execute_query_with_tx,
    tx_sender::{FeePayingType, PrerequisiteTx},
};
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, FeeRate, Transaction, Txid,
};
use std::{ops::DerefMut, str::FromStr};

impl Database {
    pub async fn confirm_transactions(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: i32,
    ) -> Result<(), BridgeError> {
        // Update tx_sender_fee_payer_utxos
        sqlx::query(
            r#"
            WITH relevant_txs AS (
                SELECT txid
                FROM bitcoin_syncer_txs
                WHERE block_id = $1
            ),
            relevant_spent_utxos AS (
                SELECT txid, vout
                FROM bitcoin_syncer_spent_utxos
                WHERE block_id = $1
            )

            -- Update tx_sender_activate_prerequisite_txs
            UPDATE tx_sender_activate_prerequisite_txs AS tap
            SET seen_block_id = $1
            WHERE tap.txid IN (SELECT txid FROM relevant_txs)
            AND tap.seen_block_id IS NULL;

            -- Update tx_sender_cancel_try_to_send_txids
            UPDATE tx_sender_cancel_try_to_send_txids AS ctt
            SET seen_block_id = $1
            WHERE ctt.txid IN (SELECT txid FROM relevant_txs)
            AND ctt.seen_block_id IS NULL;

            -- Update tx_sender_cancel_try_to_send_outpoints
            UPDATE tx_sender_cancel_try_to_send_outpoints AS cto
            SET seen_block_id = $1
            WHERE (cto.txid, cto.vout) IN (SELECT txid, vout FROM relevant_spent_utxos)
            AND cto.seen_block_id IS NULL;

            -- Update tx_sender_fee_payer_utxos
            UPDATE tx_sender_fee_payer_utxos AS fpu
            SET confirmed_block_id = $1
            WHERE fpu.fee_payer_txid IN (SELECT txid FROM relevant_txs)
            AND fpu.confirmed_block_id IS NULL;
            "#,
        )
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
            SET confirmed_block_id = NULL
            WHERE fpu.confirmed_block_id = $1;
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
    /// * `bumped_txid` - The txid of the bumped transaction
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
            "INSERT INTO tx_sender_fee_payer_utxos (bumped_tx_id, fee_payer_txid, vout, amount, replacement_of_id) 
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
            WHERE fpu.bumped_txid = $1
              AND fpu.is_confirmed = false
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

    // /// Gets the fee payer transaction details by bumped_txid and script_pubkey.
    // ///
    // /// # Arguments
    // /// * `tx` - Optional database transaction
    // /// * `bumped_txid` - The txid of the bumped transaction
    // /// * `script_pubkey` - The script pubkey of the UTXO
    // ///
    // /// # Returns
    // /// * `Result<Vec<(Txid, u32, Amount, bool)>, BridgeError>` - Vector of (fee_payer_txid, vout, amount, is_confirmed)
    // pub async fn get_fee_payer_tx(
    //     &self,
    //     tx: Option<DatabaseTransaction<'_, '_>>,
    //     bumped_id: i32,
    // ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError> {
    //     let query = sqlx::query_as(
    //         "SELECT fee_payer_txid, vout, amount, is_confirmed
    //          FROM tx_sender_fee_payer_utxos
    //          WHERE bumped_tx_id = $1",
    //     )
    //     .bind(bumped_id);

    //     let results: Vec<(String, i32, i64, bool)> =
    //         execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

    //     let mut txs = Vec::new();
    //     for (fee_payer_txid, vout, amount, is_confirmed) in results {
    //         txs.push((
    //             Txid::from_str(&fee_payer_txid).expect("Invalid fee payer txid"),
    //             vout as u32,
    //             Amount::from_sat(amount as u64),
    //             is_confirmed,
    //         ));
    //     }

    //     Ok(txs)
    // }

    pub async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        id: i32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64)>(
            "SELECT fee_payer_txid, vout, amount 
             FROM tx_sender_fee_payer_utxos fpu
             WHERE fpu.bumped_txid = $1 AND fpu.is_confirmed = true",
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
             WHERE fpu.bumped_txid = $1 AND fpu.is_confirmed = false",
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

    // /// Gets txids of txs that are unconfirmed and have a lower effective fee rate than the given fee rate.
    // pub async fn get_unconfirmed_bumpable_txs(
    //     &self,
    //     tx: Option<DatabaseTransaction<'_, '_>>,
    //     new_effective_fee_rate: FeeRate,
    // ) -> Result<Vec<Txid>, BridgeError> {
    //     let query = sqlx::query_as::<_, (TxidDB,)>(
    //         "SELECT txid
    //          FROM tx_sender_txs
    //          WHERE is_confirmed = false AND (effective_fee_rate IS NULL OR effective_fee_rate < $1)",
    //     )
    //     .bind(new_effective_fee_rate.to_sat_per_vb_ceil() as i64);

    //     let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
    //     Ok(results.into_iter().map(|(txid,)| txid.0).collect())
    // }

    pub async fn save_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        raw_tx: &Transaction,
        fee_paying_type: FeePayingType,
    ) -> Result<i32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO tx_sender_try_to_send_txs (raw_tx, fee_paying_type) VALUES ($1, $2) RETURNING id"
        )
        .bind(serialize(raw_tx))
        .bind(fee_paying_type.to_string());

        let id: i32 = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok(id)
    }

    pub async fn save_cancelled_outpoint(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        cancelled_id: i32,
        outpoint: bitcoin::OutPoint,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_cancel_try_to_send_outpoints (cancelled_id, outpoint) VALUES ($1, $2)"
        )
        .bind(cancelled_id)
        .bind(OutPointDB(outpoint));

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
    ) -> Result<Vec<(i32, FeePayingType)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, String)>(
            "WITH valid_activated_txs AS (
                SELECT activated_id
                FROM tx_sender_activate_prerequisite_txs AS activate
                JOIN bitcoin_syncer AS syncer ON activate.seen_block_id = syncer.id
                WHERE (syncer.height + activate.timelock) <= $2
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
            UPDATE tx_sender_try_to_send_txs
            SET latest_active_at = NOW()
            WHERE latest_active_at IS NULL;
            
            SELECT txs.id, txs.fee_paying_type
            FROM tx_sender_try_to_send_txs AS txs
            WHERE txs.id IN (SELECT activated_id FROM valid_activated_txs)
                AND txs.id NOT IN (SELECT cancelled_id FROM valid_cancel_outpoints)
                AND txs.id NOT IN (SELECT cancelled_id FROM valid_cancel_txids)
                AND (txs.effective_fee_rate IS NULL OR txs.effective_fee_rate <= $1);",
        )
        .bind(fee_rate.to_sat_per_vb_ceil() as i64)
        .bind(current_tip_height as i64);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        let txs = results
            .into_iter()
            .map(|(id, fee_paying_type)| {
                Ok((
                    id,
                    FeePayingType::from_str(&fee_paying_type).expect("Invalid fee paying type"),
                ))
            })
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
    ) -> Result<Transaction, BridgeError> {
        let query = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT raw_tx 
             FROM tx_sender_try_to_send_txs 
             WHERE id = $1 LIMIT 1",
        )
        .bind(id);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok(deserialize(&result.0).expect("Failed to deserialize tx"))
    }
}

// #[cfg(test)]
// mod tests {
//     // Imports required for create_test_config_with_thread_name macro.
//     use crate::config::BridgeConfig;
//     use crate::utils::initialize_logger;
//     use crate::{create_test_config_with_thread_name, database::Database, initialize_database};

//     use super::*;
//     use bitcoin::hashes::Hash;

//     #[tokio::test]
//     async fn test_fee_payer_tx_operations() {
//         let config = create_test_config_with_thread_name!(None);
//         let db = Database::new(&config).await.unwrap();

//         let bumped_id = 1;
//         let fee_payer_txid = Txid::hash(&[2u8; 32]);
//         let vout = 1;
//         let amount = 50000;

//         // Save fee payer tx
//         db.save_fee_payer_tx(
//             None,
//             bumped_id,
//             fee_payer_txid,
//             vout,
//             Amount::from_sat(amount),
//             None,
//         )
//         .await
//         .unwrap();

//         // get

//         let fee_payer_txs = db.get_fee_payer_tx(None, bumped_id).await.unwrap();
//         assert_eq!(fee_payer_txs.len(), 1);
//         assert_eq!(fee_payer_txs[0].0, fee_payer_txid);
//         assert_eq!(fee_payer_txs[0].1, vout);
//         assert_eq!(fee_payer_txs[0].2, Amount::from_sat(amount));
//         assert!(!fee_payer_txs[0].3);

//         // // Check unconfirmed txs
//         // let unconfirmed = db.get_unconfirmed_fee_payer_txs(None).await.unwrap();
//         // assert_eq!(unconfirmed.len(), 1);
//         // assert_eq!(
//         //     unconfirmed[0],
//         //     (bumped_txid, fee_payer_txid, vout, script_pubkey, amount)
//         // );

//         // // Confirm tx
//         // let blockhash = Txid::hash(&[3u8; 32]);
//         // db.confirm_fee_payer_tx(None, fee_payer_txid, blockhash)
//         //     .await
//         //     .unwrap();

//         // // Check unconfirmed txs again
//         // let unconfirmed = db.get_unconfirmed_fee_payer_txs(None).await.unwrap();
//         // assert_eq!(unconfirmed.len(), 0);
//     }

//     #[tokio::test]
//     async fn test_get_fee_payer_tx() {
//         let config = create_test_config_with_thread_name!(None);
//         let db = Database::new(&config).await.unwrap();

//         let bumped_id = 1;
//         let fee_payer_txid = Txid::hash(&[2u8; 32]);
//         let vout = 1;
//         let amount = 50000;

//         // Save fee payer tx
//         db.save_fee_payer_tx(
//             None,
//             bumped_id,
//             fee_payer_txid,
//             vout,
//             Amount::from_sat(amount),
//             None,
//         )
//         .await
//         .unwrap();

//         // Get and verify the fee payer tx details
//         let result = db.get_fee_payer_tx(None, bumped_id).await.unwrap();

//         assert_eq!(result.len(), 1);
//         let (result_txid, result_vout, result_amount, is_confirmed) = result[0];
//         assert_eq!(result_txid, fee_payer_txid);
//         assert_eq!(result_vout, vout);
//         assert_eq!(result_amount, Amount::from_sat(amount));
//         assert!(!is_confirmed);

//         // Confirm the transaction
//         let blockhash = bitcoin::BlockHash::all_zeros();
//         db.confirm_fee_payer_tx(None, fee_payer_txid, blockhash)
//             .await
//             .unwrap();

//         // Check confirmed transaction
//         let result = db.get_fee_payer_tx(None, bumped_id).await.unwrap();
//         assert_eq!(result.len(), 1);
//         let (_, _, _, is_confirmed) = result[0];
//         assert!(is_confirmed);

//         // Test non-existent tx
//         assert!(db
//             .get_fee_payer_tx(None, bumped_id + 1)
//             .await
//             .unwrap()
//             .is_empty());
//     }
// }
