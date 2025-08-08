//! # Verifier Related Database Operations
//!
//! This module includes database functions which are mainly used by a verifier.

use std::ops::DerefMut;

use super::{
    wrapper::{BlockHashDB, TxidDB, XOnlyPublicKeyDB},
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::{BlockHash, OutPoint, Txid, XOnlyPublicKey};
use eyre::Context;
use sqlx::QueryBuilder;

impl Database {
    /// Returns the last deposit index.
    /// If no deposits exist, returns None
    pub async fn get_last_deposit_idx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_as::<_, (i32,)>("SELECT COALESCE(MAX(idx), -1) FROM withdrawals");
        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        if result.0 == -1 {
            Ok(None)
        } else {
            Ok(Some(result.0 as u32))
        }
    }

    /// Returns the last withdrawal index where withdrawal_utxo_txid exists.
    /// If no withdrawals with UTXOs exist, returns None.
    pub async fn get_last_withdrawal_idx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_as::<_, (i32,)>(
            "SELECT COALESCE(MAX(idx), -1) FROM withdrawals WHERE withdrawal_utxo_txid IS NOT NULL",
        );
        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        if result.0 == -1 {
            Ok(None)
        } else {
            Ok(Some(result.0 as u32))
        }
    }

    pub async fn upsert_move_to_vault_txid_from_citrea_deposit(
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

    pub async fn get_move_to_vault_txid_from_citrea_deposit(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        citrea_idx: u32,
    ) -> Result<Option<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (TxidDB,)>(
            "SELECT move_to_vault_txid FROM withdrawals WHERE idx = $1",
        )
        .bind(i32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to i32")?);

        let result: Option<(TxidDB,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result.map(|(move_to_vault_txid,)| move_to_vault_txid.0))
    }

    pub async fn update_replacement_deposit_move_txid(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        idx: u32,
        new_move_txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "UPDATE withdrawals
             SET move_to_vault_txid = $2
             WHERE idx = $1
             RETURNING idx",
        )
        .bind(i32::try_from(idx).wrap_err("Failed to convert idx to i32")?)
        .bind(TxidDB(new_move_txid))
        .fetch_optional(tx.deref_mut())
        .await?;

        if query.is_none() {
            return Err(eyre::eyre!("Replacement move txid not found: {}", idx).into());
        }
        Ok(())
    }

    pub async fn update_withdrawal_utxo_from_citrea_withdrawal(
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

    /// For the given deposit index, returns the withdrawal utxo associated with it
    /// If there is no withdrawal utxo set for the deposit, an error is returned
    pub async fn get_withdrawal_utxo_from_citrea_withdrawal(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        citrea_idx: u32,
    ) -> Result<OutPoint, BridgeError> {
        let query = sqlx::query_as::<_, (Option<TxidDB>, Option<i32>)>(
            "SELECT w.withdrawal_utxo_txid, w.withdrawal_utxo_vout
             FROM withdrawals w
             WHERE w.idx = $1",
        )
        .bind(i32::try_from(citrea_idx).wrap_err("Failed to convert citrea index to i32")?);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match results {
            None => Err(eyre::eyre!("Deposit with id {} is not set", citrea_idx).into()),
            Some((txid, vout)) => match (txid, vout) {
                (Some(txid), Some(vout)) => Ok(OutPoint {
                    txid: txid.0,
                    vout: u32::try_from(vout)
                        .wrap_err("Failed to convert withdrawal utxo vout to u32")?,
                }),
                _ => {
                    Err(eyre::eyre!("Withdrawal utxo is not set for deposit {}", citrea_idx).into())
                }
            },
        }
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
    pub async fn update_payout_txs_and_payer_operator_xonly_pk(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        payout_txs_and_payer_operator_xonly_pk: Vec<(
            u32,
            Txid,
            Option<XOnlyPublicKey>,
            bitcoin::BlockHash,
        )>,
    ) -> Result<(), BridgeError> {
        if payout_txs_and_payer_operator_xonly_pk.is_empty() {
            return Ok(());
        }
        // Convert all values first, propagating any errors
        let converted_values: Result<Vec<_>, BridgeError> = payout_txs_and_payer_operator_xonly_pk
            .iter()
            .map(|(idx, txid, operator_xonly_pk, block_hash)| {
                Ok((
                    i32::try_from(*idx).wrap_err("Failed to convert payout index to i32")?,
                    TxidDB(*txid),
                    operator_xonly_pk.map(XOnlyPublicKeyDB),
                    BlockHashDB(*block_hash),
                ))
            })
            .collect();
        let converted_values = converted_values?;

        let mut query_builder = QueryBuilder::new(
            "UPDATE withdrawals AS w SET
                payout_txid = c.payout_txid,
                payout_payer_operator_xonly_pk = c.payout_payer_operator_xonly_pk,
                payout_tx_blockhash = c.payout_tx_blockhash
                FROM (",
        );

        query_builder.push_values(
            converted_values.into_iter(),
            |mut b, (idx, txid, operator_xonly_pk, block_hash)| {
                b.push_bind(idx)
                    .push_bind(txid)
                    .push_bind(operator_xonly_pk)
                    .push_bind(block_hash);
            },
        );

        query_builder
            .push(") AS c(idx, payout_txid, payout_payer_operator_xonly_pk, payout_tx_blockhash) WHERE w.idx = c.idx");

        let query = query_builder.build();
        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_payout_info_from_move_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        move_to_vault_txid: Txid,
    ) -> Result<Option<(Option<XOnlyPublicKey>, BlockHash, Txid, i32)>, BridgeError> {
        let query = sqlx::query_as::<_, (Option<XOnlyPublicKeyDB>, BlockHashDB, TxidDB, i32)>(
            "SELECT w.payout_payer_operator_xonly_pk, w.payout_tx_blockhash, w.payout_txid, w.idx
             FROM withdrawals w
             WHERE w.move_to_vault_txid = $1",
        )
        .bind(TxidDB(move_to_vault_txid));

        let result: Option<(Option<XOnlyPublicKeyDB>, BlockHashDB, TxidDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        result
            .map(|(operator_xonly_pk, block_hash, txid, deposit_idx)| {
                Ok((
                    operator_xonly_pk.map(|pk| pk.0),
                    block_hash.0,
                    txid.0,
                    deposit_idx,
                ))
            })
            .transpose()
    }

    pub async fn get_first_unhandled_payout_by_operator_xonly_pk(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
    ) -> Result<Option<(u32, Txid, BlockHash)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, Option<TxidDB>, Option<BlockHashDB>)>(
            "SELECT w.idx, w.move_to_vault_txid, w.payout_tx_blockhash
             FROM withdrawals w
             WHERE w.payout_txid IS NOT NULL
                AND w.is_payout_handled = FALSE
                AND w.payout_payer_operator_xonly_pk = $1
                ORDER BY w.idx ASC
             LIMIT 1",
        )
        .bind(XOnlyPublicKeyDB(operator_xonly_pk));

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

    pub async fn get_payer_xonly_pk_blockhash_and_kickoff_txid_from_deposit_id(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_id: u32,
    ) -> Result<(Option<XOnlyPublicKey>, Option<BlockHash>, Option<Txid>), BridgeError> {
        let query = sqlx::query_as::<
            _,
            (
                Option<XOnlyPublicKeyDB>,
                Option<BlockHashDB>,
                Option<TxidDB>,
            ),
        >(
            "SELECT w.payout_payer_operator_xonly_pk, w.payout_tx_blockhash, w.kickoff_txid
             FROM withdrawals w
             INNER JOIN deposits d ON d.move_to_vault_txid = w.move_to_vault_txid
             WHERE d.deposit_id = $1",
        )
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?);

        let result: (
            Option<XOnlyPublicKeyDB>,
            Option<BlockHashDB>,
            Option<TxidDB>,
        ) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        Ok((
            result.0.map(|pk| pk.0),
            result.1.map(|block_hash| block_hash.0),
            result.2.map(|txid| txid.0),
        ))
    }

    pub async fn update_payout_handled(
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
        database::Database,
        test::common::{create_test_config_with_thread_name, generate_random_xonly_pk},
    };
    use bitcoin::{hashes::Hash, BlockHash, Txid};

    #[tokio::test]
    async fn update_get_payout_txs_from_citrea_withdrawal() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([0x45; 32]);
        let index = 0x1F;
        let operator_xonly_pk = generate_random_xonly_pk();
        let utxo = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x45; 32]),
            vout: 0,
        };

        let mut dbtx = db.begin_transaction().await.unwrap();

        let block_id = db
            .insert_block_info(
                Some(&mut dbtx),
                &BlockHash::all_zeros(),
                &BlockHash::all_zeros(),
                utxo.vout,
            )
            .await
            .unwrap();
        db.insert_txid_to_block(&mut dbtx, block_id, &txid)
            .await
            .unwrap();
        db.insert_spent_utxo(&mut dbtx, block_id, &txid, &utxo.txid, utxo.vout.into())
            .await
            .unwrap();

        assert!(db
            .get_withdrawal_utxo_from_citrea_withdrawal(Some(&mut dbtx), index)
            .await
            .is_err());
        db.upsert_move_to_vault_txid_from_citrea_deposit(Some(&mut dbtx), index, &txid)
            .await
            .unwrap();
        db.update_withdrawal_utxo_from_citrea_withdrawal(Some(&mut dbtx), index, utxo, block_id)
            .await
            .unwrap();

        let block_hash = BlockHash::all_zeros();

        db.update_payout_txs_and_payer_operator_xonly_pk(
            Some(&mut dbtx),
            vec![(index, txid, Some(operator_xonly_pk), block_hash)],
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
            .unwrap();
        assert_eq!(withdrawal_utxo, utxo);

        let move_txid = db
            .get_move_to_vault_txid_from_citrea_deposit(Some(&mut dbtx), index)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(move_txid, txid);

        // Test payout info retrieval with Some operator xonly pk
        let payout_info = db
            .get_payout_info_from_move_txid(Some(&mut dbtx), move_txid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payout_info.0, Some(operator_xonly_pk));
        assert_eq!(payout_info.1, block_hash);
        assert_eq!(payout_info.2, txid);
        assert_eq!(payout_info.3, index as i32);

        // Test with None operator xonly pk (optimistic payout or incorrect payout)
        let index2 = 0x2F;
        let txid2 = Txid::from_byte_array([0x55; 32]);
        let utxo2 = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x55; 32]),
            vout: 1,
        };

        db.insert_txid_to_block(&mut dbtx, block_id, &txid2)
            .await
            .unwrap();
        db.insert_spent_utxo(&mut dbtx, block_id, &txid2, &utxo2.txid, utxo2.vout.into())
            .await
            .unwrap();

        db.upsert_move_to_vault_txid_from_citrea_deposit(Some(&mut dbtx), index2, &txid2)
            .await
            .unwrap();
        db.update_withdrawal_utxo_from_citrea_withdrawal(Some(&mut dbtx), index2, utxo2, block_id)
            .await
            .unwrap();

        // Set payout with None operator xonly pk
        db.update_payout_txs_and_payer_operator_xonly_pk(
            Some(&mut dbtx),
            vec![(index2, txid2, None, block_hash)],
        )
        .await
        .unwrap();

        // Test payout info retrieval with None operator xonly pk
        let payout_info2 = db
            .get_payout_info_from_move_txid(Some(&mut dbtx), txid2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payout_info2.0, None); // No operator xonly pk
        assert_eq!(payout_info2.1, block_hash);
        assert_eq!(payout_info2.2, txid2);
        assert_eq!(payout_info2.3, index2 as i32);

        // Verify we now have 2 payout transactions
        let all_txs = db
            .get_payout_txs_for_withdrawal_utxos(Some(&mut dbtx), block_id)
            .await
            .unwrap();
        assert_eq!(all_txs.len(), 2);
    }
}
