//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.

use super::wrapper::{OutPointDB, SignatureDB, SignaturesDB, TxOutDB, TxidDB, UtxoDB};
use super::Database;
use crate::errors::BridgeError;
use crate::UTXO;
use bitcoin::secp256k1::schnorr;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use sqlx::{Postgres, QueryBuilder};

pub type RootHash = [u8; 32];
pub type PublicInputWots = Vec<[u8; 20]>;
pub type AssertTxAddrs = Vec<ScriptBuf>;

pub type BitvmSetup = (AssertTxAddrs, RootHash, PublicInputWots);

impl Database {
    #[tracing::instrument(skip(self, slash_or_take_sigs), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_slash_or_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        slash_or_take_sigs: impl IntoIterator<Item = schnorr::Signature>,
    ) -> Result<(), BridgeError> {
        QueryBuilder::new(
            "UPDATE deposit_kickoff_utxos
             SET slash_or_take_sig = batch.sig
             FROM (",
        )
        .push_values(
            slash_or_take_sigs.into_iter().enumerate(),
            |mut builder, (i, slash_or_take_sig)| {
                builder
                    .push_bind(i as i32)
                    .push_bind(SignatureDB(slash_or_take_sig));
            },
        )
        .push(
            ") AS batch (operator_idx, sig)
             WHERE deposit_kickoff_utxos.deposit_outpoint = ",
        )
        .push_bind(OutPointDB(deposit_outpoint))
        .push(" AND deposit_kickoff_utxos.operator_idx = batch.operator_idx;")
        .build()
        .execute(&self.connection)
        .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_slash_or_take_sig(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
    ) -> Result<Option<schnorr::Signature>, BridgeError> {
        let qr: Option<(SignatureDB,)> = sqlx::query_as(
            "SELECT slash_or_take_sig
             FROM deposit_kickoff_utxos
             WHERE deposit_outpoint = $1 AND kickoff_utxo = $2;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(sqlx::types::Json(UtxoDB {
            outpoint_db: OutPointDB(kickoff_utxo.outpoint),
            txout_db: TxOutDB(kickoff_utxo.txout),
        }))
        .fetch_optional(&self.connection)
        .await?;

        match qr {
            Some(sig) => Ok(Some(sig.0 .0)),
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_deposit_kickoff_generator_tx(
        &self,
        txid: Txid,
    ) -> Result<Option<(String, usize, usize, Txid)>, BridgeError> {
        let qr: Option<(String, i32, i32, TxidDB)> = sqlx::query_as("SELECT raw_signed_tx, num_kickoffs, cur_unused_kickoff_index, funding_txid FROM deposit_kickoff_generator_txs WHERE txid = $1;")
            .bind(TxidDB(txid))
            .fetch_optional(&self.connection)
            .await?;

        match qr {
            Some((raw_hex, num_kickoffs, cur_unused_kickoff_index, funding_txid)) => Ok(Some((
                raw_hex,
                num_kickoffs as usize,
                cur_unused_kickoff_index as usize,
                funding_txid.0,
            ))),
            None => Ok(None),
        }
    }

    /// Saves the deposit signatures to the database for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    #[tracing::instrument(skip(self, tx, signatures), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_deposit_signatures(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        operator_idx: u32,
        signatures: Vec<schnorr::Signature>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO deposit_signatures (deposit_outpoint, operator_idx, signatures) VALUES ($1, $2, $3);"
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(operator_idx as i64)
        .bind(SignaturesDB(signatures));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Saves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_bitvm_setup(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
        sequential_collateral_tx_idx: i32,
        kickoff_idx: i32,
        assert_tx_addrs: impl AsRef<[ScriptBuf]>,
        root_hash: &[u8; 32],
        public_input_wots: impl AsRef<[[u8; 20]]>,
    ) -> Result<(), BridgeError> {
        // Convert public_input_wots Vec<[u8; 20]> to Vec<Vec<u8>> for PostgreSQL array compatibility
        let public_input_wots: Vec<Vec<u8>> = public_input_wots
            .as_ref()
            .iter()
            .map(|arr| arr.to_vec())
            .collect();

        let query = sqlx::query(
            "INSERT INTO bitvm_setups (operator_idx, sequential_collateral_tx_idx, kickoff_idx, assert_tx_addrs, root_hash, public_input_wots)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (operator_idx, sequential_collateral_tx_idx, kickoff_idx) DO UPDATE
             SET assert_tx_addrs = EXCLUDED.assert_tx_addrs,
                 root_hash = EXCLUDED.root_hash,
                 public_input_wots = EXCLUDED.public_input_wots;"
        )
        .bind(operator_idx)
        .bind(sequential_collateral_tx_idx)
        .bind(kickoff_idx)
        .bind(assert_tx_addrs.as_ref().iter().map(|addr| addr.as_ref()).collect::<Vec<&[u8]>>())
        .bind(root_hash.to_vec())
        .bind(&public_input_wots);

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Retrieves the deposit signatures for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_deposit_signatures(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        operator_idx: u32,
    ) -> Result<Option<Vec<schnorr::Signature>>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT signatures FROM deposit_signatures WHERE deposit_outpoint = $1 AND operator_idx = $2;"
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(operator_idx as i64);

        let result: Result<(SignaturesDB,), sqlx::Error> = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        };

        match result {
            Ok((SignaturesDB(signatures),)) => Ok(Some(signatures)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Retrieves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_bitvm_setup(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
        sequential_collateral_tx_idx: i32,
        kickoff_idx: i32,
    ) -> Result<Option<BitvmSetup>, BridgeError> {
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>, Vec<u8>, Vec<Vec<u8>>)>(
            "SELECT assert_tx_addrs, root_hash, public_input_wots
             FROM bitvm_setups
             WHERE operator_idx = $1 AND sequential_collateral_tx_idx = $2 AND kickoff_idx = $3;",
        )
        .bind(operator_idx)
        .bind(sequential_collateral_tx_idx)
        .bind(kickoff_idx);

        let result = match tx {
            Some(tx) => query.fetch_optional(&mut **tx).await?,
            None => query.fetch_optional(&self.connection).await?,
        };

        match result {
            Some((assert_tx_addrs, root_hash, public_input_wots)) => {
                // Convert root_hash Vec<u8> back to [u8; 32]
                let mut root_hash_array = [0u8; 32];
                root_hash_array.copy_from_slice(&root_hash);

                // Convert public_input_wots Vec<Vec<u8>> back to Vec<[u8; 20]>
                let public_input_wots: Result<Vec<[u8; 20]>, _> = public_input_wots
                    .into_iter()
                    .map(|v| {
                        let mut arr = [0u8; 20];
                        if v.len() != 20 {
                            return Err(BridgeError::Error(
                                "Invalid public_input_wots length".to_string(),
                            ));
                        }
                        arr.copy_from_slice(&v);
                        Ok(arr)
                    })
                    .collect();

                let assert_tx_addrs: Vec<ScriptBuf> = assert_tx_addrs
                    .into_iter()
                    .map(|addr| addr.into())
                    .collect();

                Ok(Some((assert_tx_addrs, root_hash_array, public_input_wots?)))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use crate::{create_test_config_with_thread_name, UTXO};
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use std::{env, thread};

    #[tokio::test]
    async fn test_operators_funding_utxo_1() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let utxo = UTXO {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 1,
            },
            txout: TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from(vec![1u8]),
            },
        };
        db.set_funding_utxo(None, utxo.clone()).await.unwrap();
        let db_utxo = db.get_funding_utxo(None).await.unwrap().unwrap();

        // Sanity check
        assert_eq!(db_utxo, utxo);
    }

    #[tokio::test]
    async fn test_operators_funding_utxo_2() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let db_utxo = db.get_funding_utxo(None).await.unwrap();

        assert!(db_utxo.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_2() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_3() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_save_get_bitvm_setup() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        let operator_idx = 0;
        let sequential_collateral_tx_idx = 1;
        let kickoff_idx = 2;
        let assert_tx_addrs = [vec![1u8; 34], vec![4u8; 34]];
        let root_hash = [42u8; 32];
        let public_input_wots = vec![[1u8; 20], [2u8; 20]];

        // Save BitVM setup
        database
            .save_bitvm_setup(
                None,
                operator_idx,
                sequential_collateral_tx_idx,
                kickoff_idx,
                assert_tx_addrs
                    .iter()
                    .map(|addr| addr.clone().into())
                    .collect::<Vec<ScriptBuf>>(),
                &root_hash,
                public_input_wots.clone(),
            )
            .await
            .unwrap();

        // Retrieve and verify
        let result = database
            .get_bitvm_setup(
                None,
                operator_idx,
                sequential_collateral_tx_idx,
                kickoff_idx,
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            result.0,
            assert_tx_addrs
                .iter()
                .map(|addr| addr.clone().into())
                .collect::<Vec<ScriptBuf>>()
        );
        assert_eq!(result.1, root_hash);
        assert_eq!(result.2, public_input_wots);

        // Test non-existent entry
        let non_existent = database
            .get_bitvm_setup(None, 999, sequential_collateral_tx_idx, kickoff_idx)
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }
}
