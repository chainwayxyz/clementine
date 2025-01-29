//! # Verifier Related Database Operations
//!
//! This module includes database functions which are mainly used by a verifier.

use super::{
    wrapper::{
        AddressDB, EVMAddressDB, MessageDB, MusigAggNonceDB, MusigPubNonceDB, OutPointDB,
        PublicKeyDB, TxOutDB, UtxoDB,
    },
    Database, DatabaseTransaction,
};
use crate::{errors::BridgeError, execute_query_with_tx, EVMAddress, UTXO};
use bitcoin::{
    address::NetworkUnchecked,
    secp256k1::{Message, PublicKey},
    Address, OutPoint,
};
use secp256k1::musig::{MusigAggNonce, MusigPubNonce};
use sqlx::QueryBuilder;

impl Database {
    /// Sets the all verifiers' public keys. Given array **must** be in the same
    /// order as the verifiers' indexes.
    pub async fn set_verifiers_public_keys(
        &self,
        tx: DatabaseTransaction<'_, '_>,
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
        tx: DatabaseTransaction<'_, '_>,
    ) -> Result<Vec<PublicKey>, BridgeError> {
        let query = sqlx::query_as("SELECT * FROM verifier_public_keys ORDER BY idx;");

        let pks: Vec<(i32, PublicKeyDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(pks.into_iter().map(|(_, pk)| pk.0).collect())
    }

    /// Sets the kickoff UTXOs for this deposit UTXO. If a record already exists,
    /// it does nothing.
    pub async fn set_kickoff_utxos(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        deposit_outpoint: OutPoint,
        kickoff_utxos: &[UTXO],
    ) -> Result<(), BridgeError> {
        let mut query_builder = QueryBuilder::new(
            "INSERT INTO deposit_kickoff_utxos (deposit_outpoint, kickoff_utxo, operator_idx) ",
        );

        query_builder.push_values(
            kickoff_utxos.iter().enumerate(),
            |mut builder, (operator_idx, utxo)| {
                builder
                    .push_bind(OutPointDB(deposit_outpoint))
                    .push_bind(sqlx::types::Json(UtxoDB {
                        outpoint_db: OutPointDB(utxo.outpoint),
                        txout_db: TxOutDB(utxo.txout.clone()),
                    }))
                    .push_bind(operator_idx as i32);
            },
        );

        // Add the ON CONFLICT clause
        query_builder.push(" ON CONFLICT (deposit_outpoint, operator_idx) DO NOTHING");

        execute_query_with_tx!(self.connection, tx, query_builder.build(), execute)?;

        Ok(())
    }

    /// Gets the verified kickoff UTXOs for a deposit UTXO.
    pub async fn get_kickoff_utxos(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<UTXO>>, BridgeError> {
        let qr: Vec<(sqlx::types::Json<UtxoDB>,)> = sqlx::query_as(
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

    /// Sets the generated pub nonces for a verifier.
    pub async fn set_nonces(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        deposit_outpoint: OutPoint,
        pub_nonces: &[MusigPubNonce],
    ) -> Result<(), BridgeError> {
        let mut query =
            QueryBuilder::new("INSERT INTO nonces (deposit_outpoint, internal_idx, pub_nonce) ");
        query.push_values(
            pub_nonces.iter().enumerate(),
            |mut builder, (idx, pub_nonce)| {
                builder
                    .push_bind(OutPointDB(deposit_outpoint))
                    .push_bind(idx as i32)
                    .push_bind(MusigPubNonceDB(*pub_nonce));
            },
        );
        let query = query.build();

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the public nonces for a deposit UTXO.
    pub async fn get_pub_nonces(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<MusigPubNonce>>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT pub_nonce FROM nonces WHERE deposit_outpoint = $1 ORDER BY internal_idx;",
        )
        .bind(OutPointDB(deposit_outpoint));

        let result: Vec<(MusigPubNonceDB,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        if result.is_empty() {
            Ok(None)
        } else {
            let pub_nonces: Vec<MusigPubNonce> = result.into_iter().map(|(x,)| x.0).collect();
            Ok(Some(pub_nonces))
        }
    }

    /// Sets the deposit info to use later.
    pub async fn set_deposit_info(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO deposit_infos (deposit_outpoint, recovery_taproot_address, evm_address) VALUES ($1, $2, $3);")
        .bind(OutPointDB(deposit_outpoint))
        .bind(AddressDB(recovery_taproot_address))
        .bind(EVMAddressDB(evm_address));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the deposit info to use later.
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

    /// Saves the sighash and returns agg nonces for the verifier. If the
    /// sighash already exists and is different, returns error.
    /// TODO: no test
    pub async fn set_sighashes_and_get_nonces(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        deposit_outpoint: OutPoint,
        index: usize,
        sighashes: &[Message],
    ) -> Result<Option<Vec<MusigAggNonce>>, BridgeError> {
        let mut query = QueryBuilder::new(
            "WITH updated AS (
                UPDATE nonces
                SET sighash = batch.sighash
                FROM (",
        );
        let query = query.push_values(sighashes.iter().enumerate(), |mut builder, (i, sighash)| {
            builder
                .push_bind((index + i) as i32)
                .push_bind(MessageDB(*sighash));
        });

        let query = query
            .push(
                ") AS batch (internal_idx, sighash)
                WHERE nonces.internal_idx = batch.internal_idx AND nonces.deposit_outpoint = ",
            )
            .push_bind(OutPointDB(deposit_outpoint))
            .push(
                " RETURNING nonces.internal_idx, agg_nonce)
                SELECT updated.agg_nonce
                FROM updated
                ORDER BY updated.internal_idx;",
            )
            .build_query_as();

        let result: Result<Vec<(MusigAggNonceDB,)>, sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all);

        match result {
            Ok(nonces) => {
                let nonces = nonces.into_iter().map(|x| x.0 .0).collect();
                Ok(Some(nonces))
            }
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Verifier: Save the agg nonces for signing
    /// TODO: no test nor getter
    pub async fn set_agg_nonces(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        deposit_outpoint: OutPoint,
        agg_nonces: impl IntoIterator<Item = &MusigAggNonce>,
    ) -> Result<(), BridgeError> {
        let mut query = QueryBuilder::new(
            "UPDATE nonces
             SET agg_nonce = batch.agg_nonce
             FROM (",
        );

        let query = query.push_values(
            agg_nonces.into_iter().enumerate(),
            |mut builder, (i, agg_nonce)| {
                builder
                    .push_bind(i as i32)
                    .push_bind(MusigAggNonceDB(*agg_nonce));
            },
        );

        let query = query
            .push(
                ") AS batch (internal_idx, agg_nonce)
             WHERE nonces.internal_idx = batch.internal_idx AND nonces.deposit_outpoint = ",
            )
            .push_bind(OutPointDB(deposit_outpoint))
            .build();

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use crate::{
        create_test_config_with_thread_name, database::Database, musig2::nonce_pair, utils::SECP,
        EVMAddress, UTXO,
    };
    use bitcoin::{
        hashes::Hash, key::Keypair, secp256k1::SecretKey, Address, Amount, OutPoint, ScriptBuf,
        TxOut, Txid, XOnlyPublicKey,
    };
    use crypto_bigint::rand_core::OsRng;
    use secp256k1::musig::MusigPubNonce;
    use std::{env, thread};

    #[tokio::test]
    async fn test_verifiers_kickoff_utxos_1() {
        let config = create_test_config_with_thread_name!(None);
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
        db.set_kickoff_utxos(None, outpoint, &kickoff_utxos)
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
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let res = db.get_kickoff_utxos(outpoint).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_get_pub_nonces_1() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let sks = [
            SecretKey::from_slice(&[1u8; 32]).unwrap(),
            SecretKey::from_slice(&[2u8; 32]).unwrap(),
            SecretKey::from_slice(&[3u8; 32]).unwrap(),
        ];
        let keypairs: Vec<Keypair> = sks
            .iter()
            .map(|sk| Keypair::from_secret_key(&SECP, sk))
            .collect();
        let pub_nonces: Vec<MusigPubNonce> = keypairs
            .into_iter()
            .map(|kp| nonce_pair(&kp, &mut OsRng).unwrap().1)
            .collect();
        db.set_nonces(None, outpoint, &pub_nonces).await.unwrap();
        let pub_nonces = db.get_pub_nonces(None, outpoint).await.unwrap().unwrap();

        // Sanity checks
        assert_eq!(pub_nonces.len(), pub_nonces.len());
        for (pub_nonce, db_pub_nonce) in pub_nonces.iter().zip(pub_nonces.iter()) {
            assert_eq!(pub_nonce, db_pub_nonce);
        }
    }

    #[tokio::test]
    async fn test_get_pub_nonces_2() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let pub_nonces = db.get_pub_nonces(None, outpoint).await.unwrap();
        assert!(pub_nonces.is_none());
    }

    #[tokio::test]
    async fn test_save_and_get_deposit_info() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();
        let outpoint = OutPoint::null();
        let taproot_address = Address::p2tr(&SECP, xonly_public_key, None, config.network);
        let evm_address = EVMAddress([1u8; 20]);
        database
            .set_deposit_info(
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
}
