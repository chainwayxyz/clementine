//! # Transaction Sender Related Database Operations
//!
//! This module includes database functions which are mainly used by the transaction sender.

use super::{Database, DatabaseTransaction};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::{Amount, BlockHash, ScriptBuf, Txid};
use std::{ops::DerefMut, str::FromStr};

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
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO fee_payer_utxos (bumped_txid, fee_payer_txid, vout, script_pubkey, amount) 
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(bumped_txid.to_string())
        .bind(fee_payer_txid.to_string())
        .bind(vout as i32)
        .bind(script_pubkey.to_string())
        .bind(amount.to_sat() as i64);

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
            "UPDATE fee_payer_utxos 
             SET is_confirmed = true, confirmed_blockhash = $1 
             WHERE fee_payer_txid = $2",
        )
        .bind(blockhash.to_string())
        .bind(fee_payer_txid.to_string());

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
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
             FROM fee_payer_utxos 
             WHERE bumped_txid = $1 AND script_pubkey = $2",
        )
        .bind(bumped_txid.to_string())
        .bind(script_pubkey.to_string());

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

    // /// Gets all unconfirmed fee payer transactions.
    // pub async fn get_unconfirmed_fee_payer_txs(
    //     &self,
    //     tx: Option<DatabaseTransaction<'_, '_>>,
    // ) -> Result<Vec<(Txid, Txid, u32, ScriptBuf, u64)>, BridgeError> {
    //     let query = sqlx::query_as(
    //         "SELECT bumped_txid, fee_payer_txid, vout, script_pubkey, amount
    //          FROM fee_payer_utxos
    //          WHERE is_confirmed = false",
    //     );

    //     let results: Vec<(String, String, i32, String, i64)> =
    //         execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

    //     let mut txs = Vec::new();
    //     for (bumped_txid, fee_payer_txid, vout, script_pubkey, amount) in results {
    //         txs.push((
    //             Txid::from_str(&bumped_txid)?,
    //             Txid::from_str(&fee_payer_txid)?,
    //             vout as u32,
    //             ScriptBuf::from_str(&script_pubkey)?,
    //             amount as u64,
    //         ));
    //     }

    //     Ok(txs)
    // }

    pub async fn set_tx_sender_chain_head(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<(BlockHash, u64), BridgeError> {
        sqlx::query("DELETE FROM tx_sender_block_info")
            .execute(tx.deref_mut())
            .await?;
        sqlx::query("INSERT INTO tx_sender_block_info (block_hash, height) VALUES ($1, $2)")
            .bind(block_hash.to_string())
            .bind(height as i64)
            .execute(tx.deref_mut())
            .await?;
        Ok((block_hash, height))
    }

    pub async fn get_tx_sender_chain_head(&self) -> Result<Option<(BlockHash, u64)>, BridgeError> {
        let mut tx = self.begin_transaction().await?;
        let ret: Option<(String, i64)> =
            sqlx::query_as("SELECT block_hash, height FROM tx_sender_block_info LIMIT 1")
                .fetch_optional(tx.deref_mut())
                .await?;
        if let Some((block_hash, height)) = ret {
            let block_hash = BlockHash::from_str(&block_hash)?;
            let height = height as u64;
            Ok(Some((block_hash, height)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    // Imports required for create_test_config_with_thread_name macro.
    use crate::config::BridgeConfig;
    use crate::utils::initialize_logger;
    use crate::{create_test_config_with_thread_name, database::Database, initialize_database};
    use std::env;
    use std::thread;

    use super::*;
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn test_fee_payer_tx_operations() {
        let config = create_test_config_with_thread_name!(None);
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
        let config = create_test_config_with_thread_name!(None);
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
        assert!(
            db.get_fee_payer_tx(None, non_existent, script_pubkey)
                .await
                .unwrap()
                .len()
                == 0
        );
    }
}
