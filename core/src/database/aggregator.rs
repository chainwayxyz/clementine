//! # Verifier Related Database Operations
//!
//! This module includes database functions which are mainly used by a verifier.

use super::{wrapper::TxidDB, Database, DatabaseTransaction};
use crate::execute_query_with_tx;
use bitcoin::Txid;
use clementine_errors::BridgeError;
use eyre;
use sqlx::QueryBuilder;

impl Database {
    /// Sets a signed emergency stop transaction for a given move transaction ID
    pub async fn insert_signed_emergency_stop_tx_if_not_exists(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        move_txid: &Txid,
        encrypted_emergency_stop_tx: &[u8],
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO emergency_stop_sigs (move_txid, emergency_stop_tx) VALUES ($1, $2)
             ON CONFLICT (move_txid) DO NOTHING;",
        )
        .bind(TxidDB(*move_txid))
        .bind(encrypted_emergency_stop_tx);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets emergency stop transactions for a list of move transaction IDs
    pub async fn get_emergency_stop_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        move_txids: Vec<Txid>,
    ) -> Result<Vec<(Txid, Vec<u8>)>, BridgeError> {
        if move_txids.is_empty() {
            return Ok(Vec::new());
        }

        let mut query_builder = QueryBuilder::new(
            "SELECT move_txid, emergency_stop_tx FROM emergency_stop_sigs WHERE move_txid IN (",
        );

        let mut separated = query_builder.separated(", ");
        for txid in &move_txids {
            separated.push_bind(TxidDB(*txid));
        }
        query_builder.push(")");

        let query = query_builder.build_query_as::<(TxidDB, Vec<u8>)>();

        let results: Vec<(TxidDB, Vec<u8>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .into_iter()
            .map(|(txid, tx_data)| Ok((txid.0, tx_data)))
            .collect::<Result<_, eyre::Report>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        builder::transaction::{TransactionType, TxHandlerBuilder},
        test::common::*,
    };
    use bitcoin::{
        consensus::{self},
        hashes::Hash,
        Transaction, Txid,
    };
    fn create_test_transaction() -> Transaction {
        let tx_handler = TxHandlerBuilder::new(TransactionType::Dummy).finalize();
        tx_handler.get_cached_tx().clone()
    }

    #[tokio::test]
    async fn test_set_get_emergency_stop_tx() {
        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();

        let move_txid = Txid::from_byte_array([1u8; 32]);
        let emergency_stop_tx = create_test_transaction();
        database
            .insert_signed_emergency_stop_tx_if_not_exists(
                None,
                &move_txid,
                &consensus::serialize(&emergency_stop_tx),
            )
            .await
            .unwrap();

        let results = database
            .get_emergency_stop_txs(None, vec![move_txid])
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, move_txid);
        assert_eq!(results[0].1, consensus::serialize(&emergency_stop_tx));

        // Test getting non-existent tx
        let non_existent_txid = Txid::from_byte_array([2u8; 32]);
        let results = database
            .get_emergency_stop_txs(None, vec![non_existent_txid])
            .await
            .unwrap();
        assert!(results.is_empty());

        // Test getting multiple txs
        let move_txid2 = Txid::from_byte_array([3u8; 32]);
        let emergency_stop_tx2 = create_test_transaction();
        database
            .insert_signed_emergency_stop_tx_if_not_exists(
                None,
                &move_txid2,
                &consensus::serialize(&emergency_stop_tx2),
            )
            .await
            .unwrap();

        let results = database
            .get_emergency_stop_txs(None, vec![move_txid, move_txid2])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        let mut results = results;
        results.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(results[0].0, move_txid);
        assert_eq!(results[0].1, consensus::serialize(&emergency_stop_tx));
        assert_eq!(results[1].0, move_txid2);
        assert_eq!(results[1].1, consensus::serialize(&emergency_stop_tx2));

        // Test updating existing tx
        let updated_tx = create_test_transaction();
        database
            .insert_signed_emergency_stop_tx_if_not_exists(
                None,
                &move_txid,
                &consensus::serialize(&updated_tx),
            )
            .await
            .unwrap();

        let results = database
            .get_emergency_stop_txs(None, vec![move_txid])
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, move_txid);
        assert_eq!(results[0].1, consensus::serialize(&updated_tx));
    }
}
