//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.

use crate::musig2::{MuSigAggNonce, MuSigPubNonce, MuSigSecNonce, MuSigSigHash};
use crate::{config::BridgeConfig, errors::BridgeError};
use crate::{EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, Txid};
use secp256k1::schnorr;
use sqlx::{Pool, Postgres, QueryBuilder};

use super::wrapper::{AddressDB, EVMAddressDB, OutPointDB, SignatureDB, TxOutDB, TxidDB, UTXODB};

#[derive(Clone, Debug)]
pub struct Database {
    connection: Pool<Postgres>,
}

impl Database {
    /// Returns a `Database` after establishing a connection to database.
    /// Returns error if database is not available.
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let url = "postgresql://".to_owned()
            + config.db_host.as_str()
            + ":"
            + config.db_port.to_string().as_str()
            + "?dbname="
            + config.db_name.as_str()
            + "&user="
            + config.db_user.as_str()
            + "&password="
            + config.db_password.as_str();
        tracing::debug!("Connecting database: {}", url);

        match sqlx::PgPool::connect(url.as_str()).await {
            Ok(c) => Ok(Self { connection: c }),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Closes database connection.
    pub async fn close(&self) {
        self.connection.close().await;
    }

    /// Drops the given database if it exists.
    pub async fn drop_database(
        config: BridgeConfig,
        database_name: &str,
    ) -> Result<(), BridgeError> {
        let url = "postgresql://".to_owned()
            + config.db_user.as_str()
            + ":"
            + config.db_password.as_str()
            + "@"
            + config.db_host.as_str();
        let conn = sqlx::PgPool::connect(url.as_str()).await?;

        let query = format!("DROP DATABASE IF EXISTS {database_name}");
        sqlx::query(&query).execute(&conn).await?;

        conn.close().await;

        Ok(())
    }

    /// Creates a new database with given name. A new database connection should
    /// be established after with `Database::new(config)` call after this.
    ///
    /// This will drop the target database if it exist.
    ///
    /// Returns a new `BridgeConfig` with updated database name. Use that
    /// `BridgeConfig` to create a new connection, using `Database::new()`.
    pub async fn create_database(
        config: BridgeConfig,
        database_name: &str,
    ) -> Result<BridgeConfig, BridgeError> {
        let url = "postgresql://".to_owned()
            + config.db_user.as_str()
            + ":"
            + config.db_password.as_str()
            + "@"
            + config.db_host.as_str();
        let conn = sqlx::PgPool::connect(url.as_str()).await?;
        Database::drop_database(config.clone(), database_name).await?;
        let query = format!(
            "CREATE DATABASE {} WITH OWNER {}",
            database_name, config.db_user
        );
        sqlx::query(&query).execute(&conn).await?;

        conn.close().await;

        let config = BridgeConfig {
            db_name: database_name.to_string(),
            ..config
        };

        Ok(config)
    }

    /// Runs given SQL string to database. Database connection must be established
    /// before calling this function.
    pub async fn run_sql(&self, raw_sql: &str) -> Result<(), BridgeError> {
        sqlx::raw_sql(raw_sql).execute(&self.connection).await?;

        Ok(())
    }

    pub async fn init_from_schema(&self) -> Result<(), BridgeError> {
        let schema = include_str!("../../../scripts/schema.sql");
        self.run_sql(schema).await
    }

    /// Starts a database transaction.
    ///
    /// Return value can be used for committing changes. If not committed,
    /// database will rollback every operation done after that call.
    pub async fn begin_transaction(
        &self,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
        match self.connection.begin().await {
            Ok(t) => Ok(t),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    pub async fn lock_operators_kickoff_utxo_table(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), BridgeError> {
        sqlx::query("LOCK TABLE operators_kickoff_utxo IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    // pub async fn unlock_operators_kickoff_utxo_table(
    //     &self,
    //     tx: &mut sqlx::Transaction<'_, Postgres>,
    // ) -> Result<(), BridgeError> {
    //     sqlx::query("UNLOCK TABLE operators_kickoff_utxo;")
    //         .execute(&mut **tx)
    //         .await?;
    //     Ok(())
    // }

    /// Operator: If operator already created a kickoff UTXO for this deposit UTXO, return it.
    pub async fn get_kickoff_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<UTXO>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT kickoff_utxo FROM operators_kickoff_utxo WHERE deposit_outpoint = $1;",
        )
        .bind(OutPointDB(deposit_outpoint));

        let result: Result<(sqlx::types::Json<UTXODB>,), sqlx::Error> = match tx {
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
                let db_error = e.as_database_error().ok_or(BridgeError::PgDatabaseError(
                    "THIS SHOULD NOT HAPPEN".to_string(),
                ))?;
                // if error is 23514, it means there is no more unused kickoffs
                if db_error.is_check_violation() {
                    Ok(None)
                } else {
                    Err(BridgeError::PgDatabaseError(db_error.to_string()))
                }
            }
        }
    }

    /// Operator: Gets the funding UTXO for kickoffs
    pub async fn get_funding_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<Option<UTXO>, BridgeError> {
        let query =
            sqlx::query_as("SELECT funding_utxo FROM funding_utxos ORDER BY id DESC LIMIT 1;");

        let result: Result<(sqlx::types::Json<UTXODB>,), sqlx::Error> = match tx {
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
    pub async fn set_funding_utxo(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        funding_utxo: UTXO,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO funding_utxos (funding_utxo) VALUES ($1);").bind(
            sqlx::types::Json(UTXODB {
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
        .bind(sqlx::types::Json(UTXODB {
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
    pub async fn get_kickoff_utxos(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<UTXO>>, BridgeError> {
        let qr: Vec<(sqlx::types::Json<UTXODB>,)> = sqlx::query_as(
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
                    .push_bind(sqlx::types::Json(UTXODB {
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
        .bind(sqlx::types::Json(UTXODB {
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
                    .push_bind(sqlx::types::Json(UTXODB {
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
        .bind(sqlx::types::Json(UTXODB {
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
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{
        config::BridgeConfig,
        create_test_config, create_test_config_with_thread_name,
        mock::common,
        musig2::{nonce_pair, MuSigAggNonce, MuSigPubNonce, MuSigSecNonce},
        ByteArray32, EVMAddress, UTXO,
    };
    use bitcoin::{
        hashes::Hash, Address, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey,
    };
    use crypto_bigint::rand_core::OsRng;
    use secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
    use secp256k1::{schnorr, Secp256k1};
    use std::thread;

    #[tokio::test]
    async fn test_database_gets_previously_saved_operator_take_signature() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let database = Database::new(config).await.unwrap();

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
    #[should_panic]
    async fn test_invalid_connection() {
        let mut config = BridgeConfig::new();
        config.db_host = "nonexistinghost".to_string();
        config.db_name = "nonexistingpassword".to_string();
        config.db_user = "nonexistinguser".to_string();
        config.db_password = "nonexistingpassword".to_string();
        config.db_port = 123;

        Database::new(config).await.unwrap();
    }

    #[tokio::test]
    async fn test_valid_connection() {
        let config = create_test_config_with_thread_name!("test_config.toml");

        Database::new(config).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_drop_database() {
        let handle = thread::current()
            .name()
            .unwrap()
            .split(':')
            .last()
            .unwrap()
            .to_owned();
        let config = common::get_test_config("test_config.toml").unwrap();
        let config = Database::create_database(config, &handle).await.unwrap();

        // Do not save return result so that connection will drop immediately.
        Database::new(config.clone()).await.unwrap();

        Database::drop_database(config, &handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_save_and_get_deposit_info() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let database = Database::new(config.clone()).await.unwrap();

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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();
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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();
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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();
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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();
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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let pub_nonces = db.get_pub_nonces(None, outpoint).await.unwrap();
        assert!(pub_nonces.is_none());
    }

    #[tokio::test]
    async fn test_operators_kickoff_utxo_1() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let db_kickoff_utxo = db.get_kickoff_utxo(None, outpoint).await.unwrap();
        assert!(db_kickoff_utxo.is_none());
    }

    #[tokio::test]
    async fn test_verifiers_kickoff_utxos_1() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let res = db.get_kickoff_utxos(outpoint).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_operators_funding_utxo_1() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

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
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

        let db_utxo = db.get_funding_utxo(None).await.unwrap();

        assert!(db_utxo.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_1() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

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
    async fn test_deposit_kickoff_generator_tx_2() {
        let config = create_test_config_with_thread_name!("test_config.toml");
        let db = Database::new(config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    // #[tokio::test]
    // async fn test_kickoff_root_1() {
    //     let config = create_test_config_with_thread_name!("test_config.toml");
    //     let db = Database::new(config).await.unwrap();

    //     let outpoint = OutPoint {
    //         txid: Txid::from_byte_array([1u8; 32]),
    //         vout: 1,
    //     };
    //     let root = [1u8; 32];
    //     db.save_kickoff_root(outpoint, root).await.unwrap();
    //     let db_root = db.get_kickoff_root(outpoint).await.unwrap().unwrap();

    //     // Sanity check
    //     assert_eq!(db_root, root);
    // }

    // #[tokio::test]
    // async fn test_kickoff_root_2() {
    //     let config = create_test_config_with_thread_name!("test_config.toml");
    //     let db = Database::new(config).await.unwrap();

    //     let outpoint = OutPoint {
    //         txid: Txid::from_byte_array([1u8; 32]),
    //         vout: 1,
    //     };
    //     let res = db.get_kickoff_root(outpoint).await.unwrap();
    //     assert!(res.is_none());
    // }
}
