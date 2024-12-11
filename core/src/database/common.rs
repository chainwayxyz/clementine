//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.

use super::wrapper::{
    AddressDB, EVMAddressDB, OutPointDB, PublicKeyDB, SignatureDB, SignaturesDB, TxOutDB, TxidDB,
    Utxodb, XOnlyPublicKeyDB,
};
use super::wrapper::{BlockHashDB, BlockHeaderDB};
use super::Database;
use crate::errors::BridgeError;
use crate::musig2::{MuSigAggNonce, MuSigPubNonce, MuSigSecNonce, MuSigSigHash};
use crate::{EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{
    block::{self, Header, Version},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use bitcoin::{Address, OutPoint, Txid};
use bitvm::bridge::transactions::signing_winternitz::WinternitzPublicKey;
use bitvm::signatures::winternitz;
use risc0_zkvm::Receipt;
use secp256k1::schnorr;
use sqlx::{Postgres, QueryBuilder};

impl Database {
    /// Verifier: save the generated sec nonce and pub nonces
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_verifier_public_keys(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        public_keys: &[secp256k1::PublicKey],
    ) -> Result<(), BridgeError> {
        let mut query = QueryBuilder::new("INSERT INTO verifier_public_keys (idx, public_key) ");
        query.push_values(public_keys.iter().enumerate(), |mut builder, (idx, pk)| {
            builder
                .push_bind(idx as i32) // Bind the index
                .push_bind(PublicKeyDB(*pk)); // Bind public key
        });
        let query = query.build();

        // Now you can use the `query` variable in the match statement
        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_verifier_public_keys(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<Vec<secp256k1::PublicKey>, BridgeError> {
        let query = sqlx::query_as("SELECT * FROM verifier_public_keys ORDER BY idx;");

        let result: Result<Vec<(i32, PublicKeyDB)>, sqlx::Error> = match tx {
            Some(tx) => query.fetch_all(&mut **tx).await,
            None => query.fetch_all(&self.connection).await,
        };

        match result {
            Ok(pks) => Ok(pks.into_iter().map(|(_, pk)| pk.0).collect()),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Verifier: save the generated sec nonce and pub nonces
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn set_time_tx(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
        idx: i32,
        time_txid: Txid,
        block_height: i32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operator_time_txs (operator_idx, idx, time_txid, block_height) VALUES ($1, $2, $3, $4);",
        )
        .bind(operator_idx)
        .bind(idx)
        .bind(TxidDB(time_txid))
        .bind(block_height);

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_time_txs(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
    ) -> Result<Vec<(i32, Txid, i32)>, BridgeError> {
        let query = sqlx::query_as("SELECT idx, time_txid, block_height FROM operator_time_txs WHERE operator_idx = $1 ORDER BY idx;").bind(operator_idx);

        let result: Result<Vec<(i32, TxidDB, i32)>, sqlx::Error> = match tx {
            Some(tx) => query.fetch_all(&mut **tx).await,
            None => query.fetch_all(&self.connection).await,
        };

        match result {
            Ok(time_txs) => Ok(time_txs
                .into_iter()
                .map(|(idx, txid_db, block_height)| (idx, txid_db.0, block_height))
                .collect()),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    pub async fn set_operator(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
        xonly_pubkey: secp256k1::XOnlyPublicKey,
        wallet_address: String,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operators (operator_idx, xonly_pk, wallet_reimburse_address) VALUES ($1, $2, $3);",
        )
        .bind(operator_idx)
        .bind(XOnlyPublicKeyDB(xonly_pubkey))
        .bind(wallet_address);

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_timeout_tx_sigs(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: u32,
        timeout_tx_sigs: Vec<schnorr::Signature>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operator_timeout_tx_sigs (operator_idx, timeout_tx_sigs) VALUES ($1, $2);",
        )
        .bind(operator_idx as i64)
        .bind(SignaturesDB(timeout_tx_sigs));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_timeout_tx_sigs(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: u32,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT timeout_tx_sigs FROM operator_timeout_tx_sigs WHERE operator_idx = $1;",
        )
        .bind(operator_idx as i64);

        let signatures: (SignaturesDB,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        Ok(signatures.0 .0)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn lock_operators_kickoff_utxo_table(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), BridgeError> {
        sqlx::query("LOCK TABLE operators_kickoff_utxo IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Operator: If operator already created a kickoff UTXO for this deposit UTXO, return it.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_kickoff_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<UTXO>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT kickoff_utxo FROM operators_kickoff_utxo WHERE deposit_outpoint = $1;",
        )
        .bind(OutPointDB(deposit_outpoint));

        let result: Result<(sqlx::types::Json<Utxodb>,), sqlx::Error> = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        };

        match result {
            Ok((utxo_db,)) => Ok(Some(UTXO {
                outpoint: utxo_db.outpoint_db.0,
                txout: utxo_db.txout_db.0.clone(),
            })),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Operator: Get unused kickoff_utxo at ready if there are any.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_unused_kickoff_utxo_and_increase_idx(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<Option<UTXO>, BridgeError> {
        // Attempt to fetch the latest transaction details
        let query = sqlx::query_as(
            "UPDATE deposit_kickoff_generator_txs
                SET cur_unused_kickoff_index = cur_unused_kickoff_index + 1
                WHERE id = (
                    SELECT id 
                    FROM deposit_kickoff_generator_txs 
                    WHERE cur_unused_kickoff_index < num_kickoffs
                    ORDER BY id DESC 
                    LIMIT 1
                )
                RETURNING txid, raw_signed_tx, cur_unused_kickoff_index;", // This query returns the updated cur_unused_kickoff_index.
        );

        let result: Result<(TxidDB, String, i32), sqlx::Error> = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        };

        match result {
            Ok((txid, raw_signed_tx, cur_unused_kickoff_index)) => {
                // Deserialize the transaction
                let tx: bitcoin::Transaction =
                    bitcoin::consensus::deserialize(&hex::decode(raw_signed_tx).unwrap())?;

                // Create the outpoint and txout
                let outpoint = OutPoint {
                    txid: txid.0,
                    vout: cur_unused_kickoff_index as u32 - 1,
                };
                let txout = tx.output[cur_unused_kickoff_index as usize - 1].clone();

                Ok(Some(UTXO { outpoint, txout }))
            }
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => {
                if let Some(postgresql_error) = e.as_database_error() {
                    // if error is 23514 (check_violation), it means there is no more unused kickoffs
                    if postgresql_error.is_check_violation() {
                        return Ok(None);
                    }
                };

                Err(BridgeError::DatabaseError(e))
            }
        }
    }

    /// Operator: Gets the funding UTXO for kickoffs
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_funding_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<Option<UTXO>, BridgeError> {
        let query =
            sqlx::query_as("SELECT funding_utxo FROM funding_utxos ORDER BY id DESC LIMIT 1;");

        let result: Result<(sqlx::types::Json<Utxodb>,), sqlx::Error> = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        };

        match result {
            Ok((utxo_db,)) => Ok(Some(UTXO {
                outpoint: utxo_db.outpoint_db.0,
                txout: utxo_db.txout_db.0.clone(),
            })),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Operator: Sets the funding UTXO for kickoffs
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn set_funding_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        funding_utxo: UTXO,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO funding_utxos (funding_utxo) VALUES ($1);").bind(
            sqlx::types::Json(Utxodb {
                outpoint_db: OutPointDB(funding_utxo.outpoint),
                txout_db: TxOutDB(funding_utxo.txout),
            }),
        );

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Operator: Save the kickoff UTXO for this deposit UTXO.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_kickoff_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operators_kickoff_utxo (deposit_outpoint, kickoff_utxo) VALUES ($1, $2);",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(sqlx::types::Json(Utxodb {
            outpoint_db: OutPointDB(kickoff_utxo.outpoint),
            txout_db: TxOutDB(kickoff_utxo.txout),
        }));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Operator: Save the signed kickoff UTXO generator tx.
    ///  Txid is the txid of the signed tx.
    /// funding_txid is the txid of the input[0].
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn add_deposit_kickoff_generator_tx(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        txid: Txid,
        raw_hex: String,
        num_kickoffs: usize,
        funding_txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO deposit_kickoff_generator_txs (txid, raw_signed_tx, num_kickoffs, cur_unused_kickoff_index, funding_txid) VALUES ($1, $2, $3, $4, $5);")
            .bind(TxidDB(txid))
            .bind(raw_hex)
            .bind(num_kickoffs as i32)
            .bind(1)
            .bind(TxidDB(funding_txid));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Verifier: Get the verified kickoff UTXOs for a deposit UTXO.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_kickoff_utxos(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<UTXO>>, BridgeError> {
        let qr: Vec<(sqlx::types::Json<Utxodb>,)> = sqlx::query_as(
            "SELECT kickoff_utxo FROM deposit_kickoff_utxos WHERE deposit_outpoint = $1 ORDER BY operator_idx ASC;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .fetch_all(&self.connection)
        .await?;
        if qr.is_empty() {
            Ok(None)
        } else {
            let utxos: Vec<UTXO> = qr
                .into_iter()
                .map(|utxo_db| UTXO {
                    outpoint: utxo_db.0.outpoint_db.0,
                    txout: utxo_db.0.txout_db.0.clone(),
                })
                .collect();
            Ok(Some(utxos))
        }
    }

    /// Verifier: Save the kickoff UTXOs for this deposit UTXO.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_kickoff_utxos(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        kickoff_utxos: &[UTXO],
    ) -> Result<(), BridgeError> {
        // Use QueryBuilder to construct a batch insert query
        let mut query_builder = QueryBuilder::new(
            "INSERT INTO deposit_kickoff_utxos (deposit_outpoint, kickoff_utxo, operator_idx) ",
        );

        // Add values using push_values
        query_builder.push_values(
            kickoff_utxos.iter().enumerate(),
            |mut builder, (operator_idx, utxo)| {
                builder
                    .push_bind(OutPointDB(deposit_outpoint)) // Bind deposit_outpoint
                    .push_bind(sqlx::types::Json(Utxodb {
                        // Bind JSON-serialized UTXO
                        outpoint_db: OutPointDB(utxo.outpoint),
                        txout_db: TxOutDB(utxo.txout.clone()),
                    }))
                    .push_bind(operator_idx as i32); // Bind the operator_idx
            },
        );

        // Add the ON CONFLICT clause
        query_builder.push(" ON CONFLICT (deposit_outpoint, operator_idx) DO NOTHING");

        // Execute the batch insert query
        match tx {
            Some(tx) => query_builder.build().execute(&mut **tx).await?,
            None => query_builder.build().execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Verifier: Get the public nonces for a deposit UTXO.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_pub_nonces(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<MuSigPubNonce>>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT pub_nonce FROM nonces WHERE deposit_outpoint = $1 ORDER BY internal_idx;",
        )
        .bind(OutPointDB(deposit_outpoint));

        let result: Vec<(MuSigPubNonce,)> = match tx {
            Some(tx) => query.fetch_all(&mut **tx).await?,
            None => query.fetch_all(&self.connection).await?,
        };
        if result.is_empty() {
            Ok(None)
        } else {
            let pub_nonces: Vec<MuSigPubNonce> = result.into_iter().map(|(x,)| x).collect();
            Ok(Some(pub_nonces))
        }
    }

    /// Verifier: save the generated sec nonce and pub nonces
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_nonces(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        nonces: &[(MuSigSecNonce, MuSigPubNonce)],
    ) -> Result<(), BridgeError> {
        let mut query = QueryBuilder::new(
            "INSERT INTO nonces (deposit_outpoint, internal_idx, sec_nonce, pub_nonce) ",
        );
        query.push_values(
            nonces.iter().enumerate(),
            |mut builder, (idx, (sec, pub_nonce))| {
                builder
                    .push_bind(OutPointDB(deposit_outpoint)) // Bind deposit_outpoint
                    .push_bind(idx as i32) // Bind the index as internal_idx
                    .push_bind(sec) // Bind sec_nonce
                    .push_bind(pub_nonce); // Bind pub_nonce
            },
        );
        let query = query.build();

        // Now you can use the `query` variable in the match statement
        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Verifier: Save the deposit info to use later
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_deposit_info(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO deposit_infos (deposit_outpoint, recovery_taproot_address, evm_address) VALUES ($1, $2, $3);")
        .bind(OutPointDB(deposit_outpoint))
        .bind(AddressDB(recovery_taproot_address))
        .bind(EVMAddressDB(evm_address));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Verifier: Get the deposit info to use later
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_deposit_info(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<(Address<NetworkUnchecked>, EVMAddress)>, BridgeError> {
        let qr: (AddressDB, EVMAddressDB) = sqlx::query_as("SELECT recovery_taproot_address, evm_address FROM deposit_infos WHERE deposit_outpoint = $1;")
            .bind(OutPointDB(deposit_outpoint))
            .fetch_one(&self.connection)
            .await?;

        Ok(Some((qr.0 .0, qr.1 .0)))
    }

    /// Verifier: saves the sighash and returns sec and agg nonces, if the sighash is already there and different, returns error
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_sighashes_and_get_nonces(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        index: usize,
        sighashes: &[MuSigSigHash],
    ) -> Result<Option<Vec<(MuSigSecNonce, MuSigAggNonce)>>, BridgeError> {
        // Update the sighashes
        let mut query = QueryBuilder::new(
            "WITH updated AS (
                UPDATE nonces
                SET sighash = batch.sighash
                FROM (",
        );
        let query = query.push_values(sighashes.iter().enumerate(), |mut builder, (i, sighash)| {
            builder.push_bind((index + i) as i32).push_bind(sighash);
        });

        let query = query
            .push(
                ") AS batch (internal_idx, sighash)
                WHERE nonces.internal_idx = batch.internal_idx AND nonces.deposit_outpoint = ",
            )
            .push_bind(OutPointDB(deposit_outpoint))
            .push(
                " RETURNING nonces.internal_idx, sec_nonce, agg_nonce)
            SELECT updated.sec_nonce, updated.agg_nonce 
            FROM updated 
            ORDER BY updated.internal_idx;",
            )
            .build_query_as();

        let result: Result<Vec<(MuSigSecNonce, MuSigAggNonce)>, sqlx::Error> = match tx {
            Some(tx) => query.fetch_all(&mut **tx).await,
            None => query.fetch_all(&self.connection).await,
        };

        match result {
            Ok(nonces) => Ok(Some(nonces)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Verifier: Save the agg nonces for signing
    #[tracing::instrument(skip(self, agg_nonces), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_agg_nonces(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        agg_nonces: impl IntoIterator<Item = &MuSigAggNonce>,
    ) -> Result<(), BridgeError> {
        let mut query = QueryBuilder::new(
            "UPDATE nonces
             SET agg_nonce = batch.agg_nonce
             FROM (",
        );

        let query = query.push_values(
            agg_nonces.into_iter().enumerate(),
            |mut builder, (i, agg_nonce)| {
                builder.push_bind(i as i32).push_bind(agg_nonce);
            },
        );

        let query = query
            .push(
                ") AS batch (internal_idx, agg_nonce)
             WHERE nonces.internal_idx = batch.internal_idx AND nonces.deposit_outpoint = ",
            )
            .push_bind(OutPointDB(deposit_outpoint))
            .build();

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };
        Ok(())
    }

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
        .bind(sqlx::types::Json(Utxodb {
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

    #[tracing::instrument(skip(self, kickoff_utxos_and_sigs), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_operator_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos_and_sigs: impl IntoIterator<Item = (UTXO, schnorr::Signature)>,
    ) -> Result<(), BridgeError> {
        QueryBuilder::new(
            "UPDATE deposit_kickoff_utxos
             SET operator_take_sig = batch.sig
             FROM (",
        )
        .push_values(
            kickoff_utxos_and_sigs,
            |mut builder, (kickoff_utxo, operator_take_sig)| {
                builder
                    .push_bind(sqlx::types::Json(Utxodb {
                        outpoint_db: OutPointDB(kickoff_utxo.outpoint),
                        txout_db: TxOutDB(kickoff_utxo.txout),
                    }))
                    .push_bind(SignatureDB(operator_take_sig));
            },
        )
        .push(
            ") AS batch (kickoff_utxo, sig)
             WHERE deposit_kickoff_utxos.deposit_outpoint = ",
        )
        .push_bind(OutPointDB(deposit_outpoint))
        .push(" AND deposit_kickoff_utxos.kickoff_utxo = batch.kickoff_utxo;")
        .build()
        .execute(&self.connection)
        .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_operator_take_sig(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
    ) -> Result<Option<schnorr::Signature>, BridgeError> {
        let qr: Option<(SignatureDB,)> = sqlx::query_as(
            "SELECT operator_take_sig
             FROM deposit_kickoff_utxos
             WHERE deposit_outpoint = $1 AND kickoff_utxo = $2;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(sqlx::types::Json(Utxodb {
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

    /// Saves a new block to the database, later to be updated by a proof.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_new_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        block_hash: block::BlockHash,
        block_header: block::Header,
        block_height: u64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
                "INSERT INTO header_chain_proofs (block_hash, block_header, prev_block_hash, height) VALUES ($1, $2, $3, $4);",
            )
            .bind(BlockHashDB(block_hash)).bind(BlockHeaderDB(block_header)).bind(BlockHashDB(block_header.prev_blockhash)).bind(block_height as i64);

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Sets a block's proof by referring to it by it's hash.
    #[tracing::instrument(skip(self, tx, proof), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_block_proof(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
        proof: Receipt,
    ) -> Result<(), BridgeError> {
        let proof = borsh::to_vec(&proof).map_err(BridgeError::BorschError)?;

        let query = sqlx::query("UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2;")
            .bind(proof)
            .bind(BlockHashDB(hash));

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Gets a block's proof by referring to it by it's hash.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_proof_by_hash(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
    ) -> Result<Option<Receipt>, BridgeError> {
        let query = sqlx::query_as("SELECT proof FROM header_chain_proofs WHERE block_hash = $1;")
            .bind(BlockHashDB(hash));

        let receipt: (Option<Vec<u8>>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;
        let receipt = match receipt.0 {
            Some(r) => r,
            None => return Ok(None),
        };

        let receipt: Receipt = borsh::from_slice(&receipt).map_err(BridgeError::BorschError)?;

        Ok(Some(receipt))
    }

    /// Returns a block's hash and header, referring it to by it's height.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_info_by_height(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        height: u64,
    ) -> Result<(block::BlockHash, block::Header), BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header FROM header_chain_proofs WHERE height = $1;",
        )
        .bind(height as i64);

        let result: (Option<BlockHashDB>, Option<BlockHeaderDB>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(hash), Some(header)) => Ok((hash.0, header.0)),
            _ => Ok((
                // TODO: Do we need to return all zeroed values or an error?
                BlockHash::all_zeros(),
                Header {
                    version: Version::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::default(),
                    nonce: 0,
                },
            )),
        }
    }

    /// Returns a block's hash and header, referring it to by it's height.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_header(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        block_height: u64,
        block_hash: BlockHash,
    ) -> Result<Option<block::Header>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_header FROM header_chain_proofs WHERE height = $1 AND block_hash = $2;",
        )
        .bind(block_height as i64)
        .bind(BlockHashDB(block_hash));

        let result: (Option<BlockHeaderDB>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(block_header),) => Ok(Some(block_header.0)),
            (None,) => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_latest_block_info(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<(u64, BlockHash), BridgeError> {
        let query = sqlx::query_as(
            "SELECT height, block_hash FROM header_chain_proofs ORDER BY height DESC;",
        );

        let result: (Option<i32>, Option<BlockHashDB>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(height), Some(hash)) => Ok((height as u64, hash.0)),
            _ => Ok((0, BlockHash::all_zeros())),
        }
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_non_proven_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<(BlockHash, Header, i32, Receipt), BridgeError> {
        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                    h1.block_header,
                    h1.height,
                    h2.proof
                FROM header_chain_proofs h1
                JOIN header_chain_proofs h2 ON h1.prev_block_hash = h2.block_hash
                WHERE h2.proof IS NOT NULL
                ORDER BY h1.height
                LIMIT 1;",
        );

        let result: (BlockHashDB, BlockHeaderDB, i32, Vec<u8>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        let receipt: Receipt = borsh::from_slice(&result.3).map_err(BridgeError::BorschError)?;

        Ok((result.0 .0, result.1 .0, result.2, receipt))
    }

    /// Sets Winternitz public keys for a watchtower.
    #[tracing::instrument(skip(self, tx, winternitz_public_keys), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_winternitz_public_key(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
        winternitz_public_keys: Vec<WinternitzPublicKey>,
    ) -> Result<(), BridgeError> {
        let wpk: Vec<_> = winternitz_public_keys
            .into_iter()
            .map(|wpk| wpk.public_key)
            .collect();
        let wpk = borsh::to_vec(&wpk).map_err(BridgeError::BorschError)?;

        let query = sqlx::query(
            "INSERT INTO winternitz_public_keys (watchtower_id, public_keys) VALUES ($1, $2);",
        )
        .bind(watchtower_id as i64)
        .bind(wpk);

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Gets Winternitz public keys for a watchtower.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_winternitz_public_key(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT public_keys FROM winternitz_public_keys WHERE watchtower_id = $1;",
        )
        .bind(watchtower_id as i64);

        let wpk: (Vec<u8>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        let winternitz_public_key: Vec<winternitz::PublicKey> = borsh::from_slice(&wpk.0).map_err(BridgeError::BorschError)?;

        Ok(winternitz_public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{
        mock::database::create_test_config_with_thread_name,
        musig2::{nonce_pair, MuSigAggNonce, MuSigPubNonce, MuSigSecNonce},
        ByteArray32, EVMAddress, UTXO,
    };
    use bitcoin::{
        block::{self, Header, Version},
        BlockHash, CompactTarget, TxMerkleNode,
    };
    use bitcoin::{
        hashes::Hash, Address, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey,
    };
    use bitvm::{
        bridge::transactions::signing_winternitz::WinternitzPublicKey,
        signatures::winternitz::{self, Parameters},
    };
    use borsh::BorshDeserialize;
    use risc0_zkvm::Receipt;
    use secp256k1::{constants::SCHNORR_SIGNATURE_SIZE, rand::rngs::OsRng};
    use secp256k1::{schnorr, Secp256k1};

    #[tokio::test]
    async fn save_get_timeout_tx_sigs() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let database = Database::new(&config).await.unwrap();

        let signatures: Vec<schnorr::Signature> = (0..0x45)
            .map(|i| schnorr::Signature::from_slice(&[i; SCHNORR_SIGNATURE_SIZE]).unwrap())
            .collect();

        database
            .save_timeout_tx_sigs(None, 0x45, signatures.clone())
            .await
            .unwrap();

        let read_signatures = database.get_timeout_tx_sigs(None, 0x45).await.unwrap();

        assert_eq!(signatures, read_signatures);
    }

    #[tokio::test]
    async fn test_database_gets_previously_saved_operator_take_signature() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let database = Database::new(&config).await.unwrap();

        let deposit_outpoint = OutPoint::null();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let kickoff_utxo = UTXO {
            outpoint,
            txout: TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from(vec![1u8]),
            },
        };
        let signature = schnorr::Signature::from_slice(&[0u8; SCHNORR_SIGNATURE_SIZE]).unwrap();

        database
            .save_kickoff_utxos(None, deposit_outpoint, &[kickoff_utxo.clone()])
            .await
            .unwrap();

        database
            .save_operator_take_sigs(deposit_outpoint, [(kickoff_utxo.clone(), signature)])
            .await
            .unwrap();

        let actual_sig = database
            .get_operator_take_sig(deposit_outpoint, kickoff_utxo)
            .await
            .unwrap();
        let expected_sig = Some(signature);

        assert_eq!(actual_sig, expected_sig);
    }

    #[tokio::test]
    async fn test_save_and_get_deposit_info() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let database = Database::new(&config).await.unwrap();

        let secp = Secp256k1::new();
        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();
        let outpoint = OutPoint::null();
        let taproot_address = Address::p2tr(&secp, xonly_public_key, None, config.network);
        let evm_address = EVMAddress([1u8; 20]);
        database
            .save_deposit_info(
                None,
                outpoint,
                taproot_address.as_unchecked().clone(),
                evm_address,
            )
            .await
            .unwrap();

        let (db_taproot_address, db_evm_address) =
            database.get_deposit_info(outpoint).await.unwrap().unwrap();

        // Sanity checks
        assert_eq!(taproot_address, db_taproot_address.assume_checked());
        assert_eq!(evm_address, db_evm_address);
    }

    #[tokio::test]
    async fn test_nonces_1() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let index = 2;
        let sighashes = [ByteArray32([1u8; 32])];
        let sks = [
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap(),
        ];
        let keypairs: Vec<secp256k1::Keypair> = sks
            .iter()
            .map(|sk| secp256k1::Keypair::from_secret_key(&secp, sk))
            .collect();
        let nonce_pairs: Vec<(MuSigSecNonce, MuSigPubNonce)> = keypairs
            .into_iter()
            .map(|kp| nonce_pair(&kp, &mut OsRng))
            .collect();
        let agg_nonces: Vec<MuSigAggNonce> = nonce_pairs
            .iter()
            .map(|(_, pub_nonce)| *pub_nonce)
            .collect();
        db.save_nonces(None, outpoint, &nonce_pairs).await.unwrap();
        db.save_agg_nonces(None, outpoint, &agg_nonces)
            .await
            .unwrap();
        let db_sec_and_agg_nonces = db
            .save_sighashes_and_get_nonces(None, outpoint, index, &sighashes)
            .await
            .unwrap()
            .unwrap();

        // Sanity checks
        assert_eq!(db_sec_and_agg_nonces.len(), 1);
        assert_eq!(db_sec_and_agg_nonces[0].0, nonce_pairs[index].0);
        assert_eq!(db_sec_and_agg_nonces[0].1, agg_nonces[index]);
    }

    #[tokio::test]
    async fn test_nonces_2() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint::null();
        let index = 0;
        let sighashes = [ByteArray32([1u8; 32]), ByteArray32([2u8; 32])];
        let sks = [
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap(),
        ];
        let keypairs: Vec<secp256k1::Keypair> = sks
            .iter()
            .map(|sk| secp256k1::Keypair::from_secret_key(&secp, sk))
            .collect();
        let nonce_pairs: Vec<(MuSigSecNonce, MuSigPubNonce)> = keypairs
            .into_iter()
            .map(|kp| nonce_pair(&kp, &mut OsRng))
            .collect();
        let agg_nonces: Vec<MuSigAggNonce> = nonce_pairs
            .iter()
            .map(|(_, pub_nonce)| *pub_nonce)
            .collect();
        db.save_nonces(None, outpoint, &nonce_pairs).await.unwrap();
        db.save_agg_nonces(None, outpoint, &agg_nonces)
            .await
            .unwrap();
        let db_sec_and_agg_nonces = db
            .save_sighashes_and_get_nonces(None, outpoint, index, &sighashes)
            .await
            .unwrap()
            .unwrap();

        // Sanity checks
        assert_eq!(db_sec_and_agg_nonces.len(), 2);
        assert_eq!(db_sec_and_agg_nonces[0].0, nonce_pairs[index].0);
        assert_eq!(db_sec_and_agg_nonces[0].1, agg_nonces[index]);
        assert_eq!(db_sec_and_agg_nonces[1].0, nonce_pairs[index + 1].0);
        assert_eq!(db_sec_and_agg_nonces[1].1, agg_nonces[index + 1]);
    }

    #[tokio::test]
    async fn test_nonces_3() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let index = 2;
        let mut sighashes = [ByteArray32([1u8; 32])];
        let sks = [
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap(),
        ];
        let keypairs: Vec<secp256k1::Keypair> = sks
            .iter()
            .map(|sk| secp256k1::Keypair::from_secret_key(&secp, sk))
            .collect();
        let nonce_pairs: Vec<(MuSigSecNonce, MuSigPubNonce)> = keypairs
            .into_iter()
            .map(|kp| nonce_pair(&kp, &mut OsRng))
            .collect();
        let agg_nonces: Vec<MuSigAggNonce> = nonce_pairs
            .iter()
            .map(|(_, pub_nonce)| *pub_nonce)
            .collect();
        db.save_nonces(None, outpoint, &nonce_pairs).await.unwrap();
        db.save_agg_nonces(None, outpoint, &agg_nonces)
            .await
            .unwrap();
        let _db_sec_and_agg_nonces = db
            .save_sighashes_and_get_nonces(None, outpoint, index, &sighashes)
            .await
            .unwrap()
            .unwrap();

        // Accidentally try to save a different sighash
        sighashes[0] = ByteArray32([2u8; 32]);
        let _db_sec_and_agg_nonces = db
            .save_sighashes_and_get_nonces(None, outpoint, index, &sighashes)
            .await
            .expect_err("Should return database sighash update error");
        println!("Error: {:?}", _db_sec_and_agg_nonces);
    }

    #[tokio::test]
    async fn test_get_pub_nonces_1() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let sks = [
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap(),
        ];
        let keypairs: Vec<secp256k1::Keypair> = sks
            .iter()
            .map(|sk| secp256k1::Keypair::from_secret_key(&secp, sk))
            .collect();
        let nonce_pairs: Vec<(MuSigSecNonce, MuSigPubNonce)> = keypairs
            .into_iter()
            .map(|kp| nonce_pair(&kp, &mut OsRng))
            .collect();
        db.save_nonces(None, outpoint, &nonce_pairs).await.unwrap();
        let pub_nonces = db.get_pub_nonces(None, outpoint).await.unwrap().unwrap();

        // Sanity checks
        assert_eq!(pub_nonces.len(), nonce_pairs.len());
        for (pub_nonce, (_, db_pub_nonce)) in pub_nonces.iter().zip(nonce_pairs.iter()) {
            assert_eq!(pub_nonce, db_pub_nonce);
        }
    }

    #[tokio::test]
    async fn test_get_pub_nonces_2() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let pub_nonces = db.get_pub_nonces(None, outpoint).await.unwrap();
        assert!(pub_nonces.is_none());
    }

    #[tokio::test]
    async fn test_operators_kickoff_utxo_1() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let kickoff_utxo = UTXO {
            outpoint,
            txout: TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from(vec![1u8]),
            },
        };
        db.save_kickoff_utxo(None, outpoint, kickoff_utxo.clone())
            .await
            .unwrap();
        let db_kickoff_utxo = db.get_kickoff_utxo(None, outpoint).await.unwrap().unwrap();

        // Sanity check
        assert_eq!(db_kickoff_utxo, kickoff_utxo);
    }

    #[tokio::test]
    async fn test_operators_kickoff_utxo_2() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let db_kickoff_utxo = db.get_kickoff_utxo(None, outpoint).await.unwrap();
        assert!(db_kickoff_utxo.is_none());
    }

    #[tokio::test]
    async fn test_verifiers_kickoff_utxos_1() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let kickoff_utxos = vec![
            UTXO {
                outpoint,
                txout: TxOut {
                    value: Amount::from_sat(100),
                    script_pubkey: ScriptBuf::from(vec![1u8]),
                },
            },
            UTXO {
                outpoint,
                txout: TxOut {
                    value: Amount::from_sat(200),
                    script_pubkey: ScriptBuf::from(vec![2u8]),
                },
            },
        ];
        db.save_kickoff_utxos(None, outpoint, &kickoff_utxos)
            .await
            .unwrap();
        let db_kickoff_utxos = db.get_kickoff_utxos(outpoint).await.unwrap().unwrap();

        // Sanity checks
        assert_eq!(db_kickoff_utxos.len(), kickoff_utxos.len());
        for (db_kickoff_utxo, kickoff_utxo) in db_kickoff_utxos.iter().zip(kickoff_utxos.iter()) {
            assert_eq!(db_kickoff_utxo, kickoff_utxo);
        }
    }

    #[tokio::test]
    async fn test_verifiers_kickoff_utxos_2() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let res = db.get_kickoff_utxos(outpoint).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_operators_funding_utxo_1() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
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
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let db_utxo = db.get_funding_utxo(None).await.unwrap();

        assert!(db_utxo.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_0() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let raw_hex = "02000000000101eb87b1a80d47b7f5bd5082b77653f5ca37e566951742b80c361875ba0e5c478f0a00000000fdffffff0ca086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3a086010000000000225120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca35c081777000000002251202a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c364a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260014005a41e6f4a4bcfcc5cd3ef602687215f97c18949019a491df56af7413c5dce9292ba3966edc4564a39d9bc0d6c0faae19030f1cedf4d931a6cdc57cc5b83c8ef00000000".to_string();
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(raw_hex.clone()).unwrap()).unwrap();
        let txid = tx.compute_txid();
        let num_kickoffs = tx.output.len() - 2;
        let funding_txid = tx.input[0].previous_output.txid;
        db.add_deposit_kickoff_generator_tx(
            None,
            txid,
            raw_hex.clone(),
            num_kickoffs,
            funding_txid,
        )
        .await
        .unwrap();
        for i in 0..num_kickoffs - 1 {
            let (db_raw_hex, db_num_kickoffs, db_cur_unused_kickoff_index, db_funding_txid) = db
                .get_deposit_kickoff_generator_tx(txid)
                .await
                .unwrap()
                .unwrap();

            // Sanity check
            assert_eq!(db_raw_hex, raw_hex);
            assert_eq!(db_num_kickoffs, num_kickoffs);
            assert_eq!(db_cur_unused_kickoff_index, i + 1);
            assert_eq!(db_funding_txid, funding_txid);

            let unused_utxo = db
                .get_unused_kickoff_utxo_and_increase_idx(None)
                .await
                .unwrap()
                .unwrap();
            println!("unused_utxo: {:?}", unused_utxo);

            // Sanity check
            assert_eq!(unused_utxo.outpoint.txid, txid);
            assert_eq!(unused_utxo.outpoint.vout, i as u32 + 1);
        }
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_2() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_1() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let raw_hex = "01000000000101308d840c736eefd114a8fad04cb0d8338b4a3034a2b517250e5498701b25eb360100000000fdffffff02401f00000000000022512024985a1ab5724a5164ae5e0026b3e7e22031e83948eedf99d438b866857946b81f7e000000000000225120f7298da2a2be5b6e02a076ff7d35a1fe6b54a2bc7938c1c86bede23cadb7d9650140ad2fdb01ec5e2772f682867c8c6f30697c63f622e338f7390d3abc6c905b9fd7e96496fdc34cb9e872387758a6a334ec1307b3505b73121e0264fe2ba546d78ad11b0d00".to_string();
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(raw_hex.clone()).unwrap()).unwrap();
        let txid = tx.compute_txid();
        let num_kickoffs = tx.output.len();
        let funding_txid = tx.input[0].previous_output.txid;
        db.add_deposit_kickoff_generator_tx(
            None,
            txid,
            raw_hex.clone(),
            num_kickoffs,
            funding_txid,
        )
        .await
        .unwrap();
        let (db_raw_hex, db_num_kickoffs, db_cur_unused_kickoff_index, db_funding_txid) = db
            .get_deposit_kickoff_generator_tx(txid)
            .await
            .unwrap()
            .unwrap();

        // Sanity check
        assert_eq!(db_raw_hex, raw_hex);
        assert_eq!(db_num_kickoffs, num_kickoffs);
        assert_eq!(db_cur_unused_kickoff_index, 1);
        assert_eq!(db_funding_txid, funding_txid);

        let unused_utxo = db
            .get_unused_kickoff_utxo_and_increase_idx(None)
            .await
            .unwrap()
            .unwrap();
        tracing::info!("unused_utxo: {:?}", unused_utxo);

        // Sanity check
        assert_eq!(unused_utxo.outpoint.txid, txid);
        assert_eq!(unused_utxo.outpoint.vout, 1);

        let none_utxo = db
            .get_unused_kickoff_utxo_and_increase_idx(None)
            .await
            .unwrap();
        assert!(none_utxo.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_3() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn save_get_new_block() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 0x45;

        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        let (read_block_hash, read_block_header) =
            db.get_block_info_by_height(None, height).await.unwrap();
        assert_eq!(block_hash, read_block_hash);
        assert_eq!(block.header, read_block_header);
    }

    #[tokio::test]
    async fn get_block_header() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let block_header = block.header;
        let block_height = 0x45;

        assert!(db
            .get_block_header(None, block_height, block_hash)
            .await
            .is_err());

        db.save_new_block(None, block_hash, block_header, block_height)
            .await
            .unwrap();
        assert_eq!(
            db.get_block_header(None, block_height, block_hash)
                .await
                .unwrap()
                .unwrap(),
            block_header
        );
    }

    #[tokio::test]
    pub async fn get_latest_chain_proof_height() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        let mut block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };

        assert!(db.get_latest_block_info(None).await.is_err());

        // Adding a new block should return a height.
        let height = 0x1F;
        let hash = block.block_hash();
        db.save_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );

        // Adding a new block with smaller height should not effect what's
        // getting returned.
        let smaller_height = height - 1;
        block.header.time = 1; // To avoid same block hash.
        db.save_new_block(None, block.block_hash(), block.header, smaller_height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );

        // Adding another block with higher height should return a different
        // height.
        let height = 0x45;
        block.header.time = 2; // To avoid same block hash.
        let hash = block.block_hash();
        db.save_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );
    }

    #[tokio::test]
    pub async fn save_get_block_proof() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        // Save dummy block.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 0x45;
        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        // Requesting proof for an existing block without a proof should
        // return `None`.
        let read_receipt = db.get_block_proof_by_hash(None, block_hash).await.unwrap();
        assert!(read_receipt.is_none());

        // Update it with a proof.
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.save_block_proof(None, block_hash, receipt.clone())
            .await
            .unwrap();

        let read_receipt = db
            .get_block_proof_by_hash(None, block_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.journal, read_receipt.journal);
        assert_eq!(receipt.metadata, read_receipt.metadata);
    }

    #[tokio::test]
    pub async fn get_non_proven_block() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let db = Database::new(&config).await.unwrap();

        assert!(db.get_non_proven_block(None).await.is_err());

        let base_height = 0x45;

        // Save initial block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = base_height;
        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

        // Save second block with a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 1,
            },
            txdata: vec![],
        };
        let block_hash1 = block.block_hash();
        let height1 = base_height + 1;
        db.save_new_block(None, block_hash1, block.header, height1)
            .await
            .unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.save_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

        // Save third block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash1,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 3,
            },
            txdata: vec![],
        };
        let block_hash2 = block.block_hash();
        let height2 = base_height + 2;
        db.save_new_block(None, block_hash2, block.header, height2)
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return second block's details.
        let res = db.get_non_proven_block(None).await.unwrap();
        assert_eq!(res.0, block_hash2);
        assert_eq!(res.2 as u64, height2);
    }

    #[tokio::test]
    async fn save_get_winternitz_public_key() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;
        let database = Database::new(&config).await.unwrap();

        let wpk: winternitz::PublicKey = vec![[0x45; 20]];
        let winternitz_public_key = vec![WinternitzPublicKey {
            public_key: wpk.clone(),
            parameters: Parameters::new(0, 4),
        }];

        database
            .save_winternitz_public_key(None, 0x45, winternitz_public_key.clone())
            .await
            .unwrap();

        let read_wpk = database
            .get_winternitz_public_key(None, 0x45)
            .await
            .unwrap();

        assert_eq!(wpk, read_wpk[0]);
    }
}
