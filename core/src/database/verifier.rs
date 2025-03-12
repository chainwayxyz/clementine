//! # Verifier Related Database Operations
//!
//! This module includes database functions which are mainly used by a verifier.

use super::{
    wrapper::{PublicKeyDB, TxidDB},
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::{secp256k1::PublicKey, OutPoint, Txid};
use sqlx::QueryBuilder;

impl Database {
    /// Sets the all verifiers' public keys. Given array **must** be in the same
    /// order as the verifiers' indexes.
    pub async fn set_verifiers_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        public_keys: &[PublicKey],
    ) -> Result<(), BridgeError> {
        let mut query = QueryBuilder::new("INSERT INTO verifier_public_keys (idx, public_key) ");
        query.push_values(public_keys.iter().enumerate(), |mut builder, (idx, pk)| {
            builder.push_bind(idx as i32).push_bind(PublicKeyDB(*pk));
        });
        let query = query.build();

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_verifiers_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Vec<PublicKey>, BridgeError> {
        let query = sqlx::query_as("SELECT * FROM verifier_public_keys ORDER BY idx;");

        let pks: Vec<(i32, PublicKeyDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(pks.into_iter().map(|(_, pk)| pk.0).collect())
    }

    pub async fn set_move_to_vault_txid_from_citrea_deposit(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        idx: u32,
        move_to_vault_txid: &Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO withdrawals (idx, move_to_vault_txid) 
             VALUES ($1, $2)
             ON CONFLICT (idx) DO UPDATE 
             SET move_to_vault_txid = $2",
        )
        .bind(i32::try_from(idx)?)
        .bind(TxidDB(*move_to_vault_txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn set_withdrawal_utxo_from_citrea_withdrawal(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        idx: u32,
        withdrawal_utxo: OutPoint,
        withdrawal_batch_proof_bitcoin_block_height: u32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE withdrawals 
             SET withdrawal_utxo_txid = $2,
                 withdrawal_utxo_vout = $3,
                 withdrawal_batch_proof_bitcoin_block_height = $4
             WHERE idx = $1",
        )
        .bind(i32::try_from(idx)?)
        .bind(TxidDB(withdrawal_utxo.txid))
        .bind(i32::try_from(withdrawal_utxo.vout)?)
        .bind(i32::try_from(withdrawal_batch_proof_bitcoin_block_height)?);

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_withdrawal_utxo_from_citrea_withdrawal(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        idx: u32,
    ) -> Result<Option<OutPoint>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB, i32)>(
            "SELECT w.withdrawal_utxo_txid, w.withdrawal_utxo_vout
             FROM withdrawals w
             WHERE w.idx = $1",
        )
        .bind(i32::try_from(idx)?);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        results
            .map(|(txid, vout)| {
                Ok(OutPoint {
                    txid: txid.0,
                    vout: u32::try_from(vout)?,
                })
            })
            .transpose()
    }

    pub async fn get_payout_txs_from_citrea_withdrawal(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_id: u32,
    ) -> Result<Vec<(u32, Txid)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, TxidDB)>(
            "SELECT w.idx, bsu.spending_txid
             FROM withdrawals w
             JOIN bitcoin_syncer_spent_utxos bsu 
                ON bsu.txid = w.withdrawal_utxo_txid 
                AND bsu.vout = w.withdrawal_utxo_vout
             WHERE bsu.block_id = $1",
        )
        .bind(i32::try_from(block_id)?);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .into_iter()
            .map(|(idx, txid)| Ok((u32::try_from(idx)?, txid.0)))
            .collect()
    }

    pub async fn set_payout_txs_and_payer_operator_idx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        payout_txs_and_payer_operator_idx: Vec<(u32, Txid, u32)>,
    ) -> Result<(), BridgeError> {
        if payout_txs_and_payer_operator_idx.is_empty() {
            return Ok(());
        }
        // Convert all values first, propagating any errors
        let converted_values: Result<Vec<_>, BridgeError> = payout_txs_and_payer_operator_idx
            .iter()
            .map(|(idx, txid, operator_idx)| {
                Ok((
                    i32::try_from(*idx)?,
                    TxidDB(*txid),
                    i32::try_from(*operator_idx)?,
                ))
            })
            .collect();
        let converted_values = converted_values?;

        let mut query_builder = QueryBuilder::new(
            "UPDATE withdrawals AS w SET 
                payout_txid = c.payout_txid,
                payout_payer_operator_idx = c.payout_payer_operator_idx
             FROM (VALUES ",
        );

        query_builder.push_values(
            converted_values.iter(),
            |mut b, (idx, txid, operator_idx)| {
                b.push_bind(idx).push_bind(txid).push_bind(operator_idx);
            },
        );

        query_builder
            .push(") AS c(idx, payout_txid, payout_payer_operator_idx) WHERE w.idx = c.idx");

        let query = query_builder.build();
        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }
}
