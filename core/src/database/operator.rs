//! # Operator Related Database Operations
//!
//! This module includes database functions which are mainly used by an operator.

use super::{
    wrapper::{OutPointDB, SignatureDB, SignaturesDB, TxOutDB, TxidDB, UtxoDB, XOnlyPublicKeyDB},
    Database, DatabaseTransaction,
};
use crate::builder::transaction::OperatorData;
use crate::{
    errors::BridgeError,
    execute_query_with_tx,
    operator::PublicHash,
    rpc::clementine::{DepositSignatures, TaggedSignature},
    UTXO,
};
use bitcoin::{secp256k1::schnorr, OutPoint, ScriptBuf, Txid, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;
use sqlx::{Postgres, QueryBuilder};
use std::str::FromStr;

pub type RootHash = [u8; 32];
//pub type PublicInputWots = Vec<[u8; 20]>;
pub type AssertTxAddrs = Vec<ScriptBuf>;

pub type BitvmSetup = (AssertTxAddrs, RootHash);

impl Database {
    /// Sets a sequential collateral tx details for an operator.
    pub async fn set_sequential_collateral_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        idx: i32,
        sequential_collateral_txid: Txid,
        block_height: i32,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operator_sequential_collateral_txs (operator_idx, idx, sequential_collateral_txid, block_height) VALUES ($1, $2, $3, $4);",
        )
        .bind(operator_idx)
        .bind(idx)
        .bind(TxidDB(sequential_collateral_txid))
        .bind(block_height);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Fetches sequential collateral tx details for an operator.
    ///
    /// # Returns
    ///
    /// - `Vec<(i32, Txid, i32)>`: A vector of tuples containing the index,
    ///   [`Txid`], and block height for a sequential collateral tx.
    pub async fn get_sequential_collateral_txs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
    ) -> Result<Vec<(i32, Txid, i32)>, BridgeError> {
        let query = sqlx::query_as("SELECT idx, sequential_collateral_txid, block_height FROM operator_sequential_collateral_txs WHERE operator_idx = $1 ORDER BY idx;").bind(operator_idx);

        let result: Vec<(i32, TxidDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(result
            .into_iter()
            .map(|(idx, txid_db, block_height)| (idx, txid_db.0, block_height))
            .collect())
    }

    /// TODO: wallet_address should have `Address` type.
    pub async fn set_operator(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        xonly_pubkey: XOnlyPublicKey,
        wallet_address: String,
        collateral_funding_txid: Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operators (operator_idx, xonly_pk, wallet_reimburse_address, collateral_funding_txid) VALUES ($1, $2, $3, $4);",
        )
        .bind(operator_idx)
        .bind(XOnlyPublicKeyDB(xonly_pubkey))
        .bind(wallet_address)
        .bind(TxidDB(collateral_funding_txid));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_operators(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Vec<(XOnlyPublicKey, bitcoin::Address, Txid)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT operator_idx, xonly_pk, wallet_reimburse_address, collateral_funding_txid FROM operators ORDER BY operator_idx;"
        );

        let operators: Vec<(i32, String, String, TxidDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        // Check for missing indices
        let indices: Vec<i32> = operators.iter().map(|(idx, _, _, _)| *idx).collect();
        let expected_indices: Vec<i32> = (0..indices.len() as i32).collect();

        if indices != expected_indices {
            return Err(BridgeError::Error(
                "Operator index is not sequential".to_string(),
            ));
        }

        // Convert the result to the desired format
        let data = operators
            .into_iter()
            .map(|(_, pk, addr, txid_db)| {
                let xonly_pk = XOnlyPublicKey::from_str(&pk)
                    .map_err(|e| BridgeError::Error(format!("Invalid XOnlyPublicKey: {}", e)))?;
                let addr = bitcoin::Address::from_str(&addr)
                    .map_err(|e| BridgeError::Error(format!("Invalid Address: {}", e)))?
                    .assume_checked();
                let txid = txid_db.0; // Extract the Txid from TxidDB
                Ok((xonly_pk, addr, txid))
            })
            .collect::<Result<Vec<_>, BridgeError>>()?;
        Ok(data)
    }

    pub async fn get_operator(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
    ) -> Result<OperatorData, BridgeError> {
        let query = sqlx::query_as(
            "SELECT operator_idx, xonly_pk, wallet_reimburse_address, collateral_funding_txid FROM operators WHERE operator_idx = $1;"
        ).bind(operator_idx);

        let (_, pk, addr, txid_db): (i32, String, String, TxidDB) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        // Convert the result to the desired format
        let xonly_pk = XOnlyPublicKey::from_str(&pk)
            .map_err(|e| BridgeError::Error(format!("Invalid XOnlyPublicKey: {}", e)))?;
        let addr = bitcoin::Address::from_str(&addr)
            .map_err(|e| BridgeError::Error(format!("Invalid Address: {}", e)))?
            .assume_checked();
        let txid = txid_db.0; // Extract the Txid from TxidDB
        Ok(OperatorData {
            xonly_pk,
            reimburse_addr: addr,
            collateral_funding_txid: txid,
        })
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

    /// Set the kickoff UTXO for this deposit UTXO.
    pub async fn set_kickoff_utxo(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operators_kickoff_utxo (deposit_outpoint, kickoff_utxo) VALUES ($1, $2);",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(sqlx::types::Json(UtxoDB {
            outpoint_db: OutPointDB(kickoff_utxo.outpoint),
            txout_db: TxOutDB(kickoff_utxo.txout),
        }));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// If operator already created a kickoff UTXO for this deposit UTXO, return it.
    pub async fn get_kickoff_utxo(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<UTXO>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT kickoff_utxo FROM operators_kickoff_utxo WHERE deposit_outpoint = $1;",
        )
        .bind(OutPointDB(deposit_outpoint));

        let result: Result<(sqlx::types::Json<UtxoDB>,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);

        match result {
            Ok((utxo_db,)) => Ok(Some(UTXO {
                outpoint: utxo_db.outpoint_db.0,
                txout: utxo_db.txout_db.0.clone(),
            })),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Get unused kickoff_utxo at ready if there are any.
    pub async fn get_unused_kickoff_utxo_and_increase_idx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
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

        let result: Result<(TxidDB, String, i32), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);

        match result {
            Ok((txid, raw_signed_tx, cur_unused_kickoff_index)) => {
                // Deserialize the transaction
                //
                let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
                    &hex::decode(raw_signed_tx).map_err(|e| BridgeError::Error(e.to_string()))?,
                )?;

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

    /// Sets the funding UTXO for kickoffs.
    pub async fn set_funding_utxo(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        funding_utxo: UTXO,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO funding_utxos (funding_utxo) VALUES ($1);").bind(
            sqlx::types::Json(UtxoDB {
                outpoint_db: OutPointDB(funding_utxo.outpoint),
                txout_db: TxOutDB(funding_utxo.txout),
            }),
        );

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the funding UTXO for kickoffs
    pub async fn get_funding_utxo(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<UTXO>, BridgeError> {
        let query =
            sqlx::query_as("SELECT funding_utxo FROM funding_utxos ORDER BY id DESC LIMIT 1;");

        let result: Result<(sqlx::types::Json<UtxoDB>,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);

        match result {
            Ok((utxo_db,)) => Ok(Some(UTXO {
                outpoint: utxo_db.outpoint_db.0,
                txout: utxo_db.txout_db.0.clone(),
            })),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    pub async fn set_operator_take_sigs(
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
                    .push_bind(sqlx::types::Json(UtxoDB {
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

    /// Sets Winternitz public keys for an operator.
    pub async fn set_operator_winternitz_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_id: u32,
        winternitz_public_key: Vec<WinternitzPublicKey>,
    ) -> Result<(), BridgeError> {
        let wpk = borsh::to_vec(&winternitz_public_key).map_err(BridgeError::BorshError)?;

        let query = sqlx::query(
                "INSERT INTO operator_winternitz_public_keys (operator_id, winternitz_public_keys) VALUES ($1, $2);",
            )
            .bind(operator_id as i64)
            .bind(wpk);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets Winternitz public keys for every sequential collateral tx of an
    /// operator and a watchtower.
    pub async fn get_operator_winternitz_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_id: u32,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let query = sqlx::query_as(
                "SELECT winternitz_public_keys FROM operator_winternitz_public_keys WHERE operator_id = $1;",
            )
            .bind(operator_id as i64);

        let wpks: (Vec<u8>,) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        let watchtower_winternitz_public_keys: Vec<winternitz::PublicKey> =
            borsh::from_slice(&wpks.0).map_err(BridgeError::BorshError)?;

        Ok(watchtower_winternitz_public_keys)
    }

    /// Sets public hashes for a specific operator, sequential collateral tx and
    /// kickoff index combination. If there is hashes for given indexes, they
    /// will be overwritten by the new hashes.
    pub async fn set_operator_challenge_ack_hashes(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        deposit_outpoint: OutPoint,
        public_hashes: &Vec<[u8; 20]>,
    ) -> Result<(), BridgeError> {
        let deposit_id = self.get_deposit_id(None, deposit_outpoint).await?;
        let query = sqlx::query(
            "INSERT INTO operators_challenge_ack_hashes (operator_idx, deposit_id, public_hashes)
             VALUES ($1, $2, $3)
             ON CONFLICT (operator_idx, deposit_id) DO UPDATE
             SET public_hashes = EXCLUDED.public_hashes;",
        )
        .bind(operator_idx)
        .bind(deposit_id)
        .bind(public_hashes);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Retrieves public hashes for a specific operator, sequential collateral
    /// tx and kickoff index combination.
    pub async fn get_operators_challenge_ack_hashes(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<PublicHash>>, BridgeError> {
        let deposit_id = self.get_deposit_id(None, deposit_outpoint).await?;
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>,)>(
            "SELECT public_hashes
            FROM operators_challenge_ack_hashes
            WHERE operator_idx = $1 AND deposit_id = $2;",
        )
        .bind(operator_idx)
        .bind(deposit_id);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((public_hashes,)) => {
                let mut converted_hashes = Vec::new();
                for hash in public_hashes {
                    match hash.try_into() {
                        Ok(public_hash) => converted_hashes.push(public_hash),
                        Err(err) => {
                            tracing::error!("Failed to convert hash: {:?}", err);
                            return Err(BridgeError::Error(
                                "Failed to convert public hash".to_string(),
                            ));
                        }
                    }
                }
                Ok(Some(converted_hashes))
            }
            None => Ok(None), // If no result is found, return Ok(None)
        }
    }

    pub async fn set_slash_or_take_sigs(
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

    /// Sets the signed kickoff UTXO generator tx.
    ///
    /// # Parameters
    ///
    /// - txid: the txid of the signed tx.
    /// - funding_txid: the txid of the input[0].
    pub async fn add_deposit_kickoff_generator_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
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

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
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

    /// Saves the deposit signatures to the database for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    pub async fn set_deposit_signatures(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
        operator_idx: usize,
        sequential_collateral_idx: usize,
        kickoff_idx: usize,
        signatures: Vec<TaggedSignature>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "WITH deposit AS (
            INSERT INTO deposits (deposit_outpoint) 
            VALUES ($1) 
            ON CONFLICT DO NOTHING 
            RETURNING deposit_id
            )
            INSERT INTO deposit_signatures (deposit_id, operator_idx, sequential_collateral_idx, kickoff_idx, signatures)
            VALUES (
            (SELECT deposit_id FROM deposit UNION SELECT deposit_id FROM deposits WHERE deposit_outpoint = $1), 
            $2, $3, $4, $5
            );"
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(operator_idx as i32)
        .bind(sequential_collateral_idx as i32)
        .bind(kickoff_idx as i32)
        .bind(SignaturesDB(DepositSignatures{signatures}));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    /// Gets a unique int for a deposit outpoint
    pub async fn get_deposit_id(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
    ) -> Result<i32, BridgeError> {
        let query = sqlx::query_as(
            "INSERT INTO deposits (deposit_outpoint)
            VALUES ($1)
            ON CONFLICT (deposit_outpoint) DO UPDATE SET deposit_outpoint = deposits.deposit_outpoint
            RETURNING deposit_id;",
        )
        .bind(OutPointDB(deposit_outpoint));
        let deposit_id: Result<(i32,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);
        Ok(deposit_id?.0)
    }

    /// Retrieves the deposit signatures for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    pub async fn get_deposit_signatures(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
        operator_idx: usize,
        sequential_collateral_idx: usize,
        kickoff_idx: usize,
    ) -> Result<Option<Vec<TaggedSignature>>, BridgeError> {
        let query = sqlx::query_as::<_, (SignaturesDB,)>(
            "SELECT ds.signatures FROM deposit_signatures ds
                    INNER JOIN deposits d ON d.deposit_id = ds.deposit_id
                 WHERE d.deposit_outpoint = $1
                 AND ds.operator_idx = $2
                 AND ds.sequential_collateral_idx = $3
                 AND ds.kickoff_idx = $4;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(operator_idx as i32)
        .bind(sequential_collateral_idx as i32)
        .bind(kickoff_idx as i32);

        let result: Result<(SignaturesDB,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);

        match result {
            Ok((SignaturesDB(signatures),)) => Ok(Some(signatures.signatures)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Saves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    pub async fn set_bitvm_setup(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        deposit_outpoint: OutPoint,
        assert_tx_addrs: impl AsRef<[ScriptBuf]>,
        root_hash: &[u8; 32],
    ) -> Result<(), BridgeError> {
        let deposit_id = self.get_deposit_id(None, deposit_outpoint).await?;
        let query = sqlx::query(
            "INSERT INTO bitvm_setups (operator_idx, deposit_id, assert_tx_addrs, root_hash)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (operator_idx, deposit_id) DO UPDATE
             SET assert_tx_addrs = EXCLUDED.assert_tx_addrs,
                 root_hash = EXCLUDED.root_hash;",
        )
        .bind(operator_idx)
        .bind(deposit_id)
        .bind(
            assert_tx_addrs
                .as_ref()
                .iter()
                .map(|addr| addr.as_ref())
                .collect::<Vec<&[u8]>>(),
        )
        .bind(root_hash.to_vec());

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Retrieves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    pub async fn get_bitvm_setup(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<BitvmSetup>, BridgeError> {
        let deposit_id = self.get_deposit_id(None, deposit_outpoint).await?;
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>, Vec<u8>)>(
            "SELECT assert_tx_addrs, root_hash
             FROM bitvm_setups
             WHERE operator_idx = $1 AND deposit_id = $2;",
        )
        .bind(operator_idx)
        .bind(deposit_id);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((assert_tx_addrs, root_hash)) => {
                // Convert root_hash Vec<u8> back to [u8; 32]
                let mut root_hash_array = [0u8; 32];
                root_hash_array.copy_from_slice(&root_hash);

                let assert_tx_addrs: Vec<ScriptBuf> = assert_tx_addrs
                    .into_iter()
                    .map(|addr| addr.into())
                    .collect();

                Ok(Some((assert_tx_addrs, root_hash_array)))
            }
            None => Ok(None),
        }
    }

    /// Retrieves BitVM disprove scripts root hash data for a specific operator, sequential collateral tx and kickoff index combination
    pub async fn get_bitvm_root_hash(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_idx: i32,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<RootHash>, BridgeError> {
        let deposit_id = self.get_deposit_id(None, deposit_outpoint).await?;
        let query = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT root_hash
             FROM bitvm_setups
             WHERE operator_idx = $1 AND deposit_id = $2;",
        )
        .bind(operator_idx)
        .bind(deposit_id);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((root_hash,)) => {
                // Convert root_hash Vec<u8> back to [u8; 32]
                let mut root_hash_array = [0u8; 32];
                root_hash_array.copy_from_slice(&root_hash);
                Ok(Some(root_hash_array))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
    use bitcoin::secp256k1::schnorr;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    use crate::extended_rpc::ExtendedRpc;
    use crate::operator::Operator;
    use crate::rpc::clementine::{
        DepositSignatures, NormalSignatureKind, TaggedSignature, WatchtowerSignatureKind,
    };
    use crate::{
        config::BridgeConfig, database::Database, initialize_database, utils::initialize_logger,
    };
    use crate::{create_regtest_rpc, create_test_config_with_thread_name, UTXO};
    use std::str::FromStr;

    #[tokio::test]
    async fn save_get_operators() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();
        let mut ops = Vec::new();
        for i in 0..2 {
            let txid_str = format!(
                "16b3a5951cb816afeb9dab8a30d0ece7acd3a7b34437436734edd1b72b6bf0{:02x}",
                i
            );
            let txid = Txid::from_str(&txid_str).unwrap();
            ops.push((
                i,
                config.operators_xonly_pks[i],
                config.operator_wallet_addresses[i].clone(),
                txid,
            ));
        }
        // add to db
        for x in ops.iter() {
            database
                .set_operator(
                    None,
                    x.0 as i32,
                    x.1,
                    x.2.clone().assume_checked().to_string(),
                    x.3,
                )
                .await
                .unwrap();
        }
        let res = database.get_operators(None).await.unwrap();
        assert_eq!(res.len(), ops.len());
        for i in 0..2 {
            assert_eq!(res[i].0, ops[i].1);
            assert_eq!(res[i].1, ops[i].2.clone().assume_checked());
            assert_eq!(res[i].2, ops[i].3);
        }

        let res_single = database.get_operator(None, 1).await.unwrap();
        assert_eq!(res_single.xonly_pk, ops[1].1);
        assert_eq!(res_single.reimburse_addr, ops[1].2.clone().assume_checked());
        assert_eq!(res_single.collateral_funding_txid, ops[1].3);
    }

    #[tokio::test]
    async fn test_save_get_public_hashes() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        let operator_idx = 0;
        let public_hashes = vec![[1u8; 20], [2u8; 20]];

        let deposit_outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        // Save public hashes
        database
            .set_operator_challenge_ack_hashes(
                None,
                operator_idx,
                deposit_outpoint,
                &public_hashes.clone(),
            )
            .await
            .unwrap();

        // Retrieve and verify
        let result = database
            .get_operators_challenge_ack_hashes(None, operator_idx, deposit_outpoint)
            .await
            .unwrap();

        assert_eq!(result, Some(public_hashes));

        // Test non-existent entry
        let non_existent = database
            .get_operators_challenge_ack_hashes(None, 999, deposit_outpoint)
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn test_database_gets_previously_saved_operator_take_signature() {
        let config = create_test_config_with_thread_name!(None);
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
            .set_kickoff_utxos(None, deposit_outpoint, &[kickoff_utxo.clone()])
            .await
            .unwrap();

        database
            .set_operator_take_sigs(deposit_outpoint, [(kickoff_utxo.clone(), signature)])
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
    async fn test_deposit_kickoff_generator_tx_0() {
        let config = create_test_config_with_thread_name!(None);
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
    async fn test_deposit_kickoff_generator_tx_1() {
        let config = create_test_config_with_thread_name!(None);
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
    async fn test_operators_kickoff_utxo_1() {
        let config = create_test_config_with_thread_name!(None);
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
        db.set_kickoff_utxo(None, outpoint, kickoff_utxo.clone())
            .await
            .unwrap();
        let db_kickoff_utxo = db.get_kickoff_utxo(None, outpoint).await.unwrap().unwrap();

        // Sanity check
        assert_eq!(db_kickoff_utxo, kickoff_utxo);
    }

    #[tokio::test]
    async fn test_operators_kickoff_utxo_2() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let db_kickoff_utxo = db.get_kickoff_utxo(None, outpoint).await.unwrap();
        assert!(db_kickoff_utxo.is_none());
    }

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
        let assert_tx_addrs = [vec![1u8; 34], vec![4u8; 34]];
        let root_hash = [42u8; 32];
        //let public_input_wots = vec![[1u8; 20], [2u8; 20]];

        let deposit_outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        // Save BitVM setup
        database
            .set_bitvm_setup(
                None,
                operator_idx,
                deposit_outpoint,
                assert_tx_addrs
                    .iter()
                    .map(|addr| addr.clone().into())
                    .collect::<Vec<ScriptBuf>>(),
                &root_hash,
            )
            .await
            .unwrap();

        // Retrieve and verify
        let result = database
            .get_bitvm_setup(None, operator_idx, deposit_outpoint)
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

        let hash = database
            .get_bitvm_root_hash(None, operator_idx, deposit_outpoint)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hash, root_hash);

        // Test non-existent entry
        let non_existent = database
            .get_bitvm_setup(None, 999, deposit_outpoint)
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn set_get_operator_winternitz_public_keys() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc!(config);
        let rpc = regtest.rpc().clone();

        let operator = Operator::new(config, rpc).await.unwrap();
        let operator_idx = 0x45;
        let wpks = operator
            .get_winternitz_public_keys(Txid::all_zeros())
            .unwrap();

        database
            .set_operator_winternitz_public_keys(None, operator_idx, wpks.clone())
            .await
            .unwrap();

        let result = database
            .get_operator_winternitz_public_keys(None, operator_idx)
            .await
            .unwrap();
        assert_eq!(result, wpks);

        let non_existent = database
            .get_operator_winternitz_public_keys(None, operator_idx + 1)
            .await;
        assert!(non_existent.is_err());
    }

    #[tokio::test]
    async fn set_get_deposit_signatures() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        let operator_idx = 0x45;
        let deposit_outpoint = OutPoint {
            txid: Txid::from_slice(&[0x45; 32]).unwrap(),
            vout: 0x1F,
        };
        let sequential_coll_idx = 1;
        let kickoff_idx = 1;
        let signatures = DepositSignatures {
            signatures: vec![
                TaggedSignature {
                    signature_id: Some(NormalSignatureKind::HappyReimburse1.into()),
                    signature: vec![0x1F; SCHNORR_SIGNATURE_SIZE],
                },
                TaggedSignature {
                    signature_id: Some((WatchtowerSignatureKind::OperatorChallengeNack1, 1).into()),
                    signature: (vec![0x2F; SCHNORR_SIGNATURE_SIZE]),
                },
            ],
        };

        database
            .set_deposit_signatures(
                None,
                deposit_outpoint,
                operator_idx,
                sequential_coll_idx,
                kickoff_idx,
                signatures.signatures.clone(),
            )
            .await
            .unwrap();

        let result = database
            .get_deposit_signatures(
                None,
                deposit_outpoint,
                operator_idx,
                sequential_coll_idx,
                kickoff_idx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, signatures.signatures);

        let non_existent = database
            .get_deposit_signatures(
                None,
                deposit_outpoint,
                operator_idx + 1,
                sequential_coll_idx + 1,
                kickoff_idx + 1,
            )
            .await
            .unwrap();
        assert!(non_existent.is_none());

        let non_existent = database
            .get_deposit_signatures(
                None,
                OutPoint::null(),
                operator_idx,
                sequential_coll_idx,
                kickoff_idx,
            )
            .await
            .unwrap();
        assert!(non_existent.is_none());

        let non_existent = database
            .get_deposit_signatures(
                None,
                OutPoint::null(),
                operator_idx + 1,
                sequential_coll_idx,
                kickoff_idx,
            )
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }
}
