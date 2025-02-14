//! # Transaction Sender Related Database Operations
//!
//! This module includes database functions which are mainly used by the transaction sender.

use super::{
    wrapper::{ScriptBufDB, TxidDB},
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::{
    consensus::{deserialize, serialize},
    Amount, FeeRate, ScriptBuf, Transaction, Txid,
};
use std::str::FromStr;

impl Database {
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
        bumped_txid: Txid,
        fee_payer_txid: Txid,
        vout: u32,
        script_pubkey: ScriptBuf,
        amount: Amount,
        replacement_of_id: Option<i32>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO tx_sender_fee_payer_utxos (bumped_txid, fee_payer_txid, vout, script_pubkey, amount, replacement_of_id) 
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(TxidDB(bumped_txid))
        .bind(TxidDB(fee_payer_txid))
        .bind(vout as i32)
        .bind(ScriptBufDB(script_pubkey))
        .bind(amount.to_sat() as i64)
        .bind(replacement_of_id);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Updates the confirmation status of a fee payer transaction.
    pub async fn confirm_fee_payer_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        fee_payer_txid: Txid,
        blockhash: bitcoin::BlockHash,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE tx_sender_fee_payer_utxos 
             SET is_confirmed = true, confirmed_blockhash = $1 
             WHERE fee_payer_txid = $2",
        )
        .bind(blockhash.to_string())
        .bind(fee_payer_txid.to_string());

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn reset_fee_payer_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        fee_payer_txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE fee_payer_utxos 
             SET is_confirmed = false, confirmed_blockhash = NULL 
             WHERE fee_payer_txid = $1",
        )
        .bind(fee_payer_txid.to_string());

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Some fee payer txs may not hit onchain, so we need to bump fees of them.
    /// These txs should not be confirmed and should not be replaced by other txs.
    /// Replaced means that the tx was bumped and the replacement tx is in the database.
    pub async fn get_bumpable_fee_payer_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        bumped_txid: Txid,
    ) -> Result<Vec<(i32, Txid, u32, Amount, ScriptBuf)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB, i32, i64, ScriptBufDB)>(
            "
            SELECT fpu.id, fpu.fee_payer_txid, fpu.vout, fpu.amount, fpu.script_pubkey
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
        .bind(super::wrapper::TxidDB(bumped_txid));

        let results: Vec<(i32, TxidDB, i32, i64, ScriptBufDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .iter()
            .map(|(id, fee_payer_txid, vout, amount, script_pubkey)| {
                (
                    *id,
                    fee_payer_txid.0,
                    *vout as u32,
                    Amount::from_sat(*amount as u64),
                    script_pubkey.0.clone(),
                )
            })
            .collect())
    }

    /// Gets the fee payer transaction details by bumped_txid and script_pubkey.
    ///
    /// # Arguments
    /// * `tx` - Optional database transaction
    /// * `bumped_txid` - The txid of the bumped transaction
    /// * `script_pubkey` - The script pubkey of the UTXO
    ///
    /// # Returns
    /// * `Result<Vec<(Txid, u32, Amount, bool)>, BridgeError>` - Vector of (fee_payer_txid, vout, amount, is_confirmed)
    pub async fn get_fee_payer_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        bumped_txid: Txid,
        script_pubkey: ScriptBuf,
    ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT fee_payer_txid, vout, amount, is_confirmed 
             FROM tx_sender_fee_payer_utxos 
             WHERE bumped_txid = $1 AND script_pubkey = $2",
        )
        .bind(super::wrapper::TxidDB(bumped_txid))
        .bind(ScriptBufDB(script_pubkey));

        let results: Vec<(String, i32, i64, bool)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        let mut txs = Vec::new();
        for (fee_payer_txid, vout, amount, is_confirmed) in results {
            txs.push((
                Txid::from_str(&fee_payer_txid).expect("Invalid fee payer txid"),
                vout as u32,
                Amount::from_sat(amount as u64),
                is_confirmed,
            ));
        }

        Ok(txs)
    }

    pub async fn get_confirmed_fee_payer_utxos(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        bumped_txid: Txid,
    ) -> Result<Vec<(Txid, u32, Amount, ScriptBuf)>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32, i64, ScriptBufDB)>(
            "SELECT fee_payer_txid, vout, amount, script_pubkey 
             FROM tx_sender_fee_payer_utxos fpu
             WHERE fpu.bumped_txid = $1 AND fpu.is_confirmed = true",
        )
        .bind(super::wrapper::TxidDB(bumped_txid));

        let results: Vec<(TxidDB, i32, i64, ScriptBufDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .iter()
            .map(|(fee_payer_txid, vout, amount, script_pubkey)| {
                (
                    fee_payer_txid.0,
                    *vout as u32,
                    Amount::from_sat(*amount as u64),
                    script_pubkey.0.clone(),
                )
            })
            .collect())
    }

    /// Gets txids of txs that are unconfirmed and have a lower effective fee rate than the given fee rate.
    pub async fn get_unconfirmed_bumpable_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        new_effective_fee_rate: FeeRate,
    ) -> Result<Vec<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB,)>(
            "SELECT txid 
             FROM tx_sender_txs 
             WHERE is_confirmed = false AND (effective_fee_rate IS NULL OR effective_fee_rate < $1)",
        )
        .bind(new_effective_fee_rate.to_sat_per_vb_ceil() as i64);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        Ok(results.into_iter().map(|(txid,)| txid.0).collect())
    }

    pub async fn save_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        txid: Txid,
        raw_tx: Transaction,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO tx_sender_txs (txid, raw_tx) VALUES ($1, $2)")
            .bind(TxidDB(txid))
            .bind(serialize(&raw_tx));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn update_effective_fee_rate(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        txid: Txid,
        effective_fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("UPDATE tx_sender_txs SET effective_fee_rate = $1 WHERE txid = $2")
            .bind(effective_fee_rate.to_sat_per_vb_ceil() as i64)
            .bind(TxidDB(txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        txid: Txid,
    ) -> Result<Transaction, BridgeError> {
        let query = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT raw_tx 
             FROM tx_sender_txs 
             WHERE txid = $1 LIMIT 1",
        )
        .bind(TxidDB(txid));

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok(deserialize(&result.0).expect("Failed to deserialize tx"))
    }
}

#[cfg(test)]
mod tests {
    // Imports required for create_test_config_with_thread_name macro.
    use crate::config::BridgeConfig;
    use crate::utils::initialize_logger;
    use crate::{create_test_config_with_thread_name, database::Database, initialize_database};

    use super::*;
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn test_fee_payer_tx_operations() {
        let mut config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let bumped_txid = Txid::hash(&[1u8; 32]);
        let fee_payer_txid = Txid::hash(&[2u8; 32]);
        let vout = 1;
        let script_pubkey = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
        let amount = 50000;

        // Save fee payer tx
        db.save_fee_payer_tx(
            None,
            bumped_txid,
            fee_payer_txid,
            vout,
            script_pubkey.clone(),
            Amount::from_sat(amount),
            None,
        )
        .await
        .unwrap();

        // get

        let fee_payer_txs = db
            .get_fee_payer_tx(None, bumped_txid, script_pubkey)
            .await
            .unwrap();
        assert_eq!(fee_payer_txs.len(), 1);
        assert_eq!(fee_payer_txs[0].0, fee_payer_txid);
        assert_eq!(fee_payer_txs[0].1, vout);
        assert_eq!(fee_payer_txs[0].2, Amount::from_sat(amount));
        assert!(!fee_payer_txs[0].3);

        // // Check unconfirmed txs
        // let unconfirmed = db.get_unconfirmed_fee_payer_txs(None).await.unwrap();
        // assert_eq!(unconfirmed.len(), 1);
        // assert_eq!(
        //     unconfirmed[0],
        //     (bumped_txid, fee_payer_txid, vout, script_pubkey, amount)
        // );

        // // Confirm tx
        // let blockhash = Txid::hash(&[3u8; 32]);
        // db.confirm_fee_payer_tx(None, fee_payer_txid, blockhash)
        //     .await
        //     .unwrap();

        // // Check unconfirmed txs again
        // let unconfirmed = db.get_unconfirmed_fee_payer_txs(None).await.unwrap();
        // assert_eq!(unconfirmed.len(), 0);
    }

    #[tokio::test]
    async fn test_get_fee_payer_tx() {
        let mut config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let bumped_txid = Txid::hash(&[1u8; 32]);
        let fee_payer_txid = Txid::hash(&[2u8; 32]);
        let vout = 1;
        let script_pubkey = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
        let amount = 50000;

        // Save fee payer tx
        db.save_fee_payer_tx(
            None,
            bumped_txid,
            fee_payer_txid,
            vout,
            script_pubkey.clone(),
            Amount::from_sat(amount),
            None,
        )
        .await
        .unwrap();

        // Get and verify the fee payer tx details
        let result = db
            .get_fee_payer_tx(None, bumped_txid, script_pubkey.clone())
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        let (result_txid, result_vout, result_amount, is_confirmed) = result[0];
        assert_eq!(result_txid, fee_payer_txid);
        assert_eq!(result_vout, vout);
        assert_eq!(result_amount, Amount::from_sat(amount));
        assert!(!is_confirmed);

        // Confirm the transaction
        let blockhash = bitcoin::BlockHash::all_zeros();
        db.confirm_fee_payer_tx(None, fee_payer_txid, blockhash)
            .await
            .unwrap();

        // Check confirmed transaction
        let result = db
            .get_fee_payer_tx(None, bumped_txid, script_pubkey.clone())
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        let (_, _, _, is_confirmed) = result[0];
        assert!(is_confirmed);

        // Test non-existent tx
        let non_existent = Txid::hash(&[0xff; 32]);
        assert!(db
            .get_fee_payer_tx(None, non_existent, script_pubkey)
            .await
            .unwrap()
            .is_empty());
    }
}
