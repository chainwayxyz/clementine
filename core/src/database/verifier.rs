//! # Verifier Related Database Operations
//!
//! This module includes database functions which are mainly used by a verifier.

use super::{
    wrapper::{BlockHashDB, PublicKeyDB, TxidDB},
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::{secp256k1::PublicKey, BlockHash, OutPoint, Txid};
use eyre::Context;
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
        citrea_idx: u32,
        move_to_vault_txid: &Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO withdrawals (idx, move_to_vault_txid)
             VALUES ($1, $2)
             ON CONFLICT (idx) DO UPDATE
             SET move_to_vault_txid = $2",
        )
        .bind(i32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to i32")?)
        .bind(TxidDB(*move_to_vault_txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn set_withdrawal_utxo_from_citrea_withdrawal(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        citrea_idx: u32,
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
        .bind(i32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to i32")?)
        .bind(TxidDB(withdrawal_utxo.txid))
        .bind(
            i32::try_from(withdrawal_utxo.vout)
                .wrap_err("Failed to convert withdrawal utxo vout to i32")?,
        )
        .bind(
            i32::try_from(withdrawal_batch_proof_bitcoin_block_height)
                .wrap_err("Failed to convert withdrawal batch proof bitcoin block height to i32")?,
        );

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_withdrawal_utxo_from_citrea_withdrawal(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        citrea_idx: u32,
    ) -> Result<Option<OutPoint>, BridgeError> {
        let query = sqlx::query_as::<_, (Option<TxidDB>, Option<i32>)>(
            "SELECT w.withdrawal_utxo_txid, w.withdrawal_utxo_vout
             FROM withdrawals w
             WHERE w.idx = $1",
        )
        .bind(i32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to i32")?);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        results
            .map(|(txid, vout)| match (txid, vout) {
                (Some(txid), Some(vout)) => Ok(OutPoint {
                    txid: txid.0,
                    vout: u32::try_from(vout)
                        .wrap_err("Failed to convert withdrawal utxo vout to u32")?,
                }),
                _ => Err(BridgeError::Error("Unexpected null value".to_string())),
            })
            .transpose()
    }

    /// Returns the withdrawal indexes and their spending txid for the given
    /// block id.
    pub async fn get_payout_txs_for_withdrawal_utxos(
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
        .bind(i32::try_from(block_id).wrap_err("Failed to convert block id to i32")?);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .into_iter()
            .map(|(idx, txid)| {
                Ok((
                    u32::try_from(idx).wrap_err("Failed to convert withdrawal index to u32")?,
                    txid.0,
                ))
            })
            .collect()
    }

    /// Sets the given payout txs' txid and operator index for the given index.
    pub async fn set_payout_txs_and_payer_operator_idx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        payout_txs_and_payer_operator_idx: Vec<(u32, Txid, u32, bitcoin::BlockHash)>,
    ) -> Result<(), BridgeError> {
        if payout_txs_and_payer_operator_idx.is_empty() {
            return Ok(());
        }
        // Convert all values first, propagating any errors
        let converted_values: Result<Vec<_>, BridgeError> = payout_txs_and_payer_operator_idx
            .iter()
            .map(|(idx, txid, operator_idx, block_hash)| {
                Ok((
                    i32::try_from(*idx).wrap_err("Failed to convert payout index to i32")?,
                    TxidDB(*txid),
                    i32::try_from(*operator_idx)
                        .wrap_err("Failed to convert payout payer operator index to i32")?,
                    BlockHashDB(*block_hash),
                ))
            })
            .collect();
        let converted_values = converted_values?;

        let mut query_builder = QueryBuilder::new(
            "UPDATE withdrawals AS w SET
                payout_txid = c.payout_txid,
                payout_payer_operator_idx = c.payout_payer_operator_idx,
                payout_tx_blockhash = c.payout_tx_blockhash
                FROM (",
        );

        query_builder.push_values(
            converted_values.into_iter(),
            |mut b, (idx, txid, operator_idx, block_hash)| {
                b.push_bind(idx)
                    .push_bind(txid)
                    .push_bind(operator_idx)
                    .push_bind(block_hash);
            },
        );

        query_builder
            .push(") AS c(idx, payout_txid, payout_payer_operator_idx, payout_tx_blockhash) WHERE w.idx = c.idx");

        let query = query_builder.build();
        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_first_unhandled_payout_by_operator_id(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_id: u32,
    ) -> Result<Option<(u32, Txid, BlockHash)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, Option<TxidDB>, Option<BlockHashDB>)>(
            "SELECT w.idx, w.move_to_vault_txid, w.payout_tx_blockhash
             FROM withdrawals w
             WHERE w.payout_txid IS NOT NULL
                AND w.is_payout_handled = FALSE
                AND w.payout_payer_operator_idx = $1
                ORDER BY w.idx ASC
             LIMIT 1",
        )
        .bind(i32::try_from(operator_id).wrap_err("Failed to convert operator id to i32")?);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        results
            .map(|(citrea_idx, move_to_vault_txid, payout_tx_blockhash)| {
                Ok((
                    u32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to u32")?,
                    move_to_vault_txid
                        .expect("move_to_vault_txid Must be Some")
                        .0,
                    payout_tx_blockhash
                        .expect("payout_tx_blockhash Must be Some")
                        .0,
                ))
            })
            .transpose()
    }

    pub async fn set_payout_handled(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        citrea_idx: u32,
        kickoff_txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE withdrawals SET is_payout_handled = TRUE, kickoff_txid = $2 WHERE idx = $1",
        )
        .bind(i32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to i32")?)
        .bind(TxidDB(kickoff_txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_handled_payout_kickoff_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        payout_txid: Txid,
    ) -> Result<Option<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (Option<TxidDB>,)>(
            "SELECT kickoff_txid FROM withdrawals WHERE payout_txid = $1 AND is_payout_handled = TRUE",
        )
        .bind(TxidDB(payout_txid));

        let result: Option<(Option<TxidDB>,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result
            .map(|(kickoff_txid,)| kickoff_txid.expect("If handled, kickoff_txid must exist").0))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bitvm_client::SECP, database::Database, test::common::create_test_config_with_thread_name,
    };
    use bitcoin::{hashes::Hash, BlockHash, Txid};

    #[tokio::test]
    async fn set_get_verifiers_public_keys() {
        let config = create_test_config_with_thread_name(None).await;
        let db = Database::new(&config).await.unwrap();

        let pks = vec![
            bitcoin::secp256k1::SecretKey::from_slice(&[1; 32])
                .unwrap()
                .public_key(&SECP),
            bitcoin::secp256k1::SecretKey::from_slice(&[2; 32])
                .unwrap()
                .public_key(&SECP),
            bitcoin::secp256k1::SecretKey::from_slice(&[3; 32])
                .unwrap()
                .public_key(&SECP),
        ];

        db.set_verifiers_public_keys(None, &pks).await.unwrap();

        let fetched_pks = db.get_verifiers_public_keys(None).await.unwrap();

        assert_eq!(pks, fetched_pks);
    }

    #[tokio::test]
    async fn set_get_payout_txs_from_citrea_withdrawal() {
        let config = create_test_config_with_thread_name(None).await;
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([0x45; 32]);
        let index = 0x1F;
        let operator_index = 0x45;
        let utxo = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x45; 32]),
            vout: 0,
        };

        let mut dbtx = db.begin_transaction().await.unwrap();

        let block_id = db
            .add_block_info(
                Some(&mut dbtx),
                &BlockHash::all_zeros(),
                &BlockHash::all_zeros(),
                utxo.vout,
            )
            .await
            .unwrap();
        db.add_txid_to_block(&mut dbtx, block_id, &txid)
            .await
            .unwrap();
        db.insert_spent_utxo(&mut dbtx, block_id, &txid, &utxo.txid, utxo.vout.into())
            .await
            .unwrap();

        assert!(db
            .get_withdrawal_utxo_from_citrea_withdrawal(Some(&mut dbtx), index)
            .await
            .unwrap()
            .is_none());
        db.set_move_to_vault_txid_from_citrea_deposit(Some(&mut dbtx), index, &txid)
            .await
            .unwrap();
        db.set_withdrawal_utxo_from_citrea_withdrawal(Some(&mut dbtx), index, utxo, block_id)
            .await
            .unwrap();

        let block_hash = BlockHash::all_zeros();

        db.set_payout_txs_and_payer_operator_idx(
            Some(&mut dbtx),
            vec![(index, txid, operator_index, block_hash)],
        )
        .await
        .unwrap();

        let txs = db
            .get_payout_txs_for_withdrawal_utxos(Some(&mut dbtx), block_id)
            .await
            .unwrap();

        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].0, index);
        assert_eq!(txs[0].1, txid);

        let withdrawal_utxo = db
            .get_withdrawal_utxo_from_citrea_withdrawal(Some(&mut dbtx), index)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(withdrawal_utxo, utxo);
    }
}
