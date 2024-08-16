//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.

use crate::musig2::{MuSigAggNonce, MuSigPubNonce, MuSigSecNonce};
use crate::{config::BridgeConfig, errors::BridgeError};
use crate::{EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, OutPoint, Txid};
use sqlx::{query, Pool, Postgres};
use std::fs;
use std::str::FromStr;

use super::wrapper::{AddressDB, EVMAddressDB, OutPointDB, TxidDB};

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

    /// Runs given SQL file to database. Database connection must be established
    /// before calling this function.
    pub async fn run_sql_file(&self, sql_file: &str) -> Result<(), BridgeError> {
        let contents = fs::read_to_string(sql_file).unwrap();

        sqlx::raw_sql(contents.as_str())
            .execute(&self.connection)
            .await?;

        Ok(())
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

    // pub async fn add_new_deposit_request(
    //     &self,
    //     start_utxo: OutPoint,
    //     recovery_taproot_address: Address<NetworkUnchecked>,
    //     evm_address: EVMAddress,
    // ) -> Result<(), BridgeError> {
    //     let start_utxo = start_utxo.to_string();
    //     let recovery_taproot_address = serde_json::to_string(&recovery_taproot_address)
    //         .unwrap()
    //         .trim_matches('"')
    //         .to_owned();
    //     let evm_address = serde_json::to_string(&evm_address)
    //         .unwrap()
    //         .trim_matches('"')
    //         .to_owned();

    //     sqlx::query("INSERT INTO new_deposit_requests (start_utxo, recovery_taproot_address, evm_address) VALUES ($1, $2, $3);")
    //         .bind(start_utxo)
    //         .bind(recovery_taproot_address)
    //         .bind(evm_address)
    //         .fetch_all(&self.connection)
    //         .await?;

    //     Ok(())
    // }

    // pub async fn get_deposit_tx(&self, idx: usize) -> Result<Txid, BridgeError> {
    //     let qr: (String,) = sqlx::query_as("SELECT move_txid FROM deposit_move_txs WHERE id = $1;")
    //         .bind(idx as i64)
    //         .fetch_one(&self.connection)
    //         .await?;

    //     match Txid::from_str(qr.0.as_str()) {
    //         Ok(c) => Ok(c),
    //         Err(e) => Err(BridgeError::DatabaseError(sqlx::Error::Decode(Box::new(e)))),
    //     }
    // }

    // pub async fn get_next_deposit_index(&self) -> Result<usize, BridgeError> {
    //     let qr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM deposit_move_txs;")
    //         .fetch_one(&self.connection)
    //         .await?;

    //     Ok(qr.0 as usize)
    // }

    // pub async fn insert_move_txid(
    //     &self,
    //     start_utxo: OutPoint,
    //     recovery_taproot_address: Address<NetworkUnchecked>,
    //     evm_address: EVMAddress,
    //     move_txid: Txid,
    // ) -> Result<(), BridgeError> {
    //     sqlx::query("INSERT INTO deposit_move_txs (start_utxo, recovery_taproot_address, evm_address, move_txid) VALUES ($1, $2, $3, $4);")
    //         .bind(start_utxo.to_string())
    //         .bind(serde_json::to_string(&recovery_taproot_address).unwrap().trim_matches('"'))
    //         .bind(serde_json::to_string(&evm_address).unwrap().trim_matches('"'))
    //         .bind(move_txid.to_string())
    //         .fetch_all(&self.connection)
    //         .await?;

    //     Ok(())
    // }

    // pub async fn get_move_txid(
    //     &self,
    //     deposit_request_utxo: OutPoint,
    //     recovery_taproot_address: Address<NetworkUnchecked>,
    //     evm_address: EVMAddress,
    // ) -> Result<Txid, BridgeError> {
    //     let qr: (String,) = sqlx::query_as("SELECT (move_txid) FROM deposit_move_txs WHERE start_utxo = $1 AND recovery_taproot_address = $2 AND evm_address = $3;")
    //         .bind(deposit_request_utxo.to_string())
    //         .bind(serde_json::to_string(&recovery_taproot_address).unwrap().trim_matches('"'))
    //         .bind(serde_json::to_string(&evm_address).unwrap().trim_matches('"'))
    //         .fetch_one(&self.connection)
    //         .await?;

    //     let move_txid = Txid::from_str(&qr.0).unwrap();
    //     Ok(move_txid)
    // }

    // pub async fn insert_deposit_flow_info(
    //     &self,
    //     deposit_request_utxo: OutPoint,
    //     recovery_taproot_address: Address<NetworkUnchecked>,
    //     evm_address: EVMAddress,
    //     move_intermediate_txid: Txid,
    //     bridge_fund_txid: Txid,
    // ) -> Result<(), BridgeError> {
    //     sqlx::query("INSERT INTO deposit_flow_infos (start_utxo, recovery_taproot_address, evm_address, move_intermediate_txid, bridge_fund_txid) VALUES ($1, $2, $3, $4, $5);")
    //         .bind(deposit_request_utxo.to_string())
    //         .bind(serde_json::to_string(&recovery_taproot_address).unwrap().trim_matches('"'))
    //         .bind(serde_json::to_string(&evm_address).unwrap().trim_matches('"'))
    //         .bind(move_intermediate_txid.to_string())
    //         .bind(bridge_fund_txid.to_string())
    //         .fetch_all(&self.connection)
    //         .await?;

    //     Ok(())
    // }

    // /// Verifier: Get the calculated bridge_fund_txid for a deposit UTXO.
    // pub async fn get_bridge_fund_txid(
    //     &self,
    //     deposit_outpoint: OutPoint,
    // ) -> Result<Txid, BridgeError> {
    //     let qr: (String,) = sqlx::query_as(
    //         "SELECT (bridge_fund_txid) FROM deposit_flow_infos WHERE start_utxo = $1;",
    //     )
    //     .bind(deposit_outpoint.to_string())
    //     .fetch_one(&self.connection)
    //     .await?;

    //     let bridge_fund_txid = Txid::from_str(&qr.0).unwrap();
    //     Ok(bridge_fund_txid)
    // }

    // pub async fn save_withdrawal_sig(
    //     &self,
    //     idx: usize,
    //     bridge_fund_txid: Txid,
    //     sig: secp256k1::schnorr::Signature,
    // ) -> Result<(), BridgeError> {
    //     sqlx::query(
    //         "INSERT INTO withdrawal_sigs (idx, bridge_fund_txid, sig) VALUES ($1, $2, $3);",
    //     )
    //     .bind(idx as i64)
    //     .bind(bridge_fund_txid.to_string())
    //     .bind(sig.to_string())
    //     .fetch_all(&self.connection)
    //     .await?;

    //     Ok(())
    // }

    // pub async fn get_withdrawal_sig_by_idx(
    //     &self,
    //     idx: usize,
    // ) -> Result<(Txid, secp256k1::schnorr::Signature), BridgeError> {
    //     let qr: (String, String) =
    //         sqlx::query_as("SELECT bridge_fund_txid, sig FROM withdrawal_sigs WHERE idx = $1;")
    //             .bind(idx as i64)
    //             .fetch_one(&self.connection)
    //             .await?;

    //     let bridge_fund_txid = Txid::from_str(&qr.0).unwrap();
    //     let sig = secp256k1::schnorr::Signature::from_str(&qr.1).unwrap();
    //     Ok((bridge_fund_txid, sig))
    // }

    /// Operator: If operator already created a kickoff UTXO for this deposit UTXO, return it.
    pub async fn get_kickoff_utxo(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<UTXO>, BridgeError> {
        let qr: (Option<UTXO>,) = sqlx::query_as(
            "SELECT kickoff_utxo FROM operators_kickoff_utxo WHERE deposit_outpoint = $1;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .fetch_one(&self.connection)
        .await?;

        Ok(qr.0)
    }

    /// Verifier: Get the verified kickoff UTXOs for a deposit UTXO.
    pub async fn get_kickoff_utxos(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<UTXO>>, BridgeError> {
        let qr: Vec<UTXO> = sqlx::query_as(
            "SELECT kickoff_utxo FROM verifiers_kickoff_utxos WHERE deposit_outpoint = $1;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .fetch_all(&self.connection)
        .await?;

        Ok(Some(qr))
    }

    /// Operator: Gets the funding UTXO for kickoffs
    pub async fn get_funding_utxo(&self) -> Result<Option<UTXO>, BridgeError> {
        let qr: (Option<UTXO>,) =
            sqlx::query_as("SELECT funding_utxo FROM funding_utxos ORDER BY id DESC LIMIT 1;")
                .fetch_one(&self.connection)
                .await?;

        Ok(qr.0)
    }

    /// Operator: Sets the funding UTXO for kickoffs
    pub async fn set_funding_utxo(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        sqlx::query("INSERT INTO funding_utxos (funding_utxo) VALUES ($1);")
            .bind(funding_utxo)
            .execute(&self.connection)
            .await?;

        Ok(())
    }

    /// Operator: Save the kickoff UTXO for this deposit UTXO. also save the funding txid to be able to track them later
    /// TODO: Change this later
    pub async fn save_kickoff_utxo(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
        funding_txid: Txid,
    ) -> Result<(), BridgeError> {
        sqlx::query(
            "INSERT INTO operators_kickoff_utxo (deposit_outpoint, kickoff_utxo, funding_txid) VALUES ($1, $2, $3);",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(kickoff_utxo)
        .bind(TxidDB(funding_txid))
        .execute(&self.connection)
        .await?;

        Ok(())
    }

    /// Verifier: Save the kickoff UTXOs for this deposit UTXO.
    pub async fn save_kickoff_utxos(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: &[UTXO],
    ) -> Result<(), BridgeError> {
        for utxo in kickoff_utxos {
            sqlx::query(
                "INSERT INTO deposit_kickoff_utxos (deposit_outpoint, kickoff_utxo) VALUES ($1, $2);",
            )
            .bind(OutPointDB(deposit_outpoint))
            .bind(utxo)
            .execute(&self.connection)
            .await?;
        }

        Ok(())
    }

    /// Verifier: Get the public nonces for a deposit UTXO.
    pub async fn get_pub_nonces(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<MuSigPubNonce>>, BridgeError> {
        let qr: Vec<MuSigPubNonce> =
            sqlx::query_as("SELECT pub_nonce FROM nonces WHERE deposit_outpoint = $1;")
                .bind(OutPointDB(deposit_outpoint))
                .fetch_all(&self.connection)
                .await?;

        Ok(Some(qr))
    }

    /// Verifier: save the generated sec nonce and pub nonces
    pub async fn save_nonces(
        &self,
        deposit_outpoint: OutPoint,
        nonces: &[(MuSigSecNonce, MuSigPubNonce)],
    ) -> Result<(), BridgeError> {
        // TODO: Use batch insert
        for (sec, pub_nonce) in nonces {
            sqlx::query(
                "INSERT INTO nonces (deposit_outpoint, sec_nonce, pub_nonce) VALUES ($1, $2, $3);",
            )
            .bind(OutPointDB(deposit_outpoint))
            .bind(sec)
            .bind(pub_nonce)
            .execute(&self.connection)
            .await?;
        }
        Ok(())
    }

    /// Verifier: Save the deposit info to use later
    pub async fn save_deposit_info(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(), BridgeError> {
        sqlx::query("INSERT INTO deposit_infos (start_utxo, recovery_taproot_address, evm_address) VALUES ($1, $2, $3);")
        .bind(OutPointDB(deposit_outpoint))
        .bind(AddressDB(recovery_taproot_address))
        .bind(EVMAddressDB(evm_address))
        .execute(&self.connection)
        .await?;

        Ok(())
    }

    /// Verifier: Get the deposit info to use later
    pub async fn get_deposit_info(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<(Address<NetworkUnchecked>, EVMAddress)>, BridgeError> {
        let qr: (AddressDB, EVMAddressDB) = sqlx::query_as("SELECT recovery_taproot_address, evm_address FROM deposit_infos WHERE start_utxo = $1;")
            .bind(OutPointDB(deposit_outpoint))
            .fetch_one(&self.connection)
            .await?;

        Ok(Some((qr.0 .0, qr.1 .0)))
    }

    /// Verifier: saves the sighash and returns sec and agg nonces, if the sighash is already there and different, returns error
    pub async fn save_sighashes_and_get_nonces(
        &self,
        deposit_outpoint: OutPoint,
        index: usize,
        sighashes: &[[u8; 32]],
    ) -> Result<Option<Vec<(MuSigSecNonce, MuSigAggNonce)>>, BridgeError> {
        let mut nonces: Vec<(MuSigSecNonce, MuSigAggNonce)> = Vec::new();
        for sighash in sighashes {
            sqlx::query(
                "INSERT INTO  nonces (deposit_outpoint, idx, sighash) VALUES ($1, $2, $3);",
            )
            .bind(OutPointDB(deposit_outpoint))
            .bind(index as i64)
            .bind(sighash)
            .fetch_one(&self.connection)
            .await?;
            let res: (MuSigSecNonce, MuSigPubNonce,) = sqlx::query_as("SELECT sec_nonce, agg_nonce FROM nonces WHERE deposit_outpoint = $1 AND idx = $2 AND sighash = $3;")
                .bind(OutPointDB(deposit_outpoint))
                .bind(index as i64)
                .bind(sighash)
                .fetch_one(&self.connection)
                .await?;
            nonces.push((res.0, res.1));
        }

        Ok(Some(nonces))
    }

    /// Verifier: Save the agg nonces for signing
    pub async fn save_agg_nonces(
        &self,
        deposit_outpoint: OutPoint,
        agg_nonces: &Vec<MuSigAggNonce>,
    ) -> Result<(), BridgeError> {
        for agg_nonce in agg_nonces {
            sqlx::query("INSERT INTO nonces (deposit_outpoint, agg_nonce) VALUES ($1, $2);")
                .bind(OutPointDB(deposit_outpoint))
                .bind(agg_nonce)
                .execute(&self.connection)
                .await?;
        }

        Ok(())
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
        transaction_builder::TransactionBuilder,
        EVMAddress,
    };
    use bitcoin::{Address, Amount, OutPoint, PublicKey, ScriptBuf, TxOut, XOnlyPublicKey};
    use crypto_bigint::rand_core::OsRng;
    use musig2::secp256k1::Keypair;
    use secp256k1::{schnorr::Signature, Secp256k1};
    use std::thread;

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
        let config = common::get_test_config("test_config.toml").unwrap();

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
        let evm_address = EVMAddress([0u8; 20]);
        database
            .save_deposit_info(
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
        let config = create_test_config!("get_save_withdrawal_sig", "test_config.toml");
        let db = Database::new(config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint::null();
        let index = 1;
        let sighashes = [[0u8; 32], [1u8; 32], [2u8; 32]];
        let sks = [
            secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
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
            .map(|(_, pub_nonce)| pub_nonce.clone())
            .collect();
        db.save_nonces(outpoint, &nonce_pairs).await.unwrap();
        db.save_agg_nonces(outpoint, &agg_nonces).await.unwrap();
        let db_sec_and_agg_nonces = db
            .save_sighashes_and_get_nonces(outpoint, index, &sighashes)
            .await
            .unwrap()
            .unwrap();

        // Sanity checks
        assert_eq!(db_sec_and_agg_nonces.len(), 3);
        for (i, (db_sec_nonce, db_agg_nonce)) in db_sec_and_agg_nonces.into_iter().enumerate() {
            assert_eq!(db_sec_nonce, nonce_pairs[i].0);
            assert_eq!(db_agg_nonce, agg_nonces[i]);
        }
    }

    #[tokio::test]
    async fn test_nonces_2() {
        let config = create_test_config!("get_save_withdrawal_sig", "test_config.toml");
        let db = Database::new(config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint::null();
        let index = 1;
        let sighashes = [[0u8; 32], [1u8; 32], [2u8; 32]];
        let sks = [
            secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
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
            .map(|(_, pub_nonce)| pub_nonce.clone())
            .collect();
        db.save_nonces(outpoint, &nonce_pairs).await.unwrap();
        db.save_agg_nonces(outpoint, &agg_nonces).await.unwrap();
        let res = db
            .save_sighashes_and_get_nonces(outpoint, index, &sighashes)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_nonces_3() {
        let config = create_test_config!("get_save_withdrawal_sig", "test_config.toml");
        let db = Database::new(config).await.unwrap();
        let secp = Secp256k1::new();

        let outpoint = OutPoint::null();
        let index = 1;
        let sighashes = [[0u8; 32], [1u8; 32], [2u8; 32]];
        let sks = [
            secp256k1::SecretKey::from_slice(&[0u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
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
            .map(|(_, pub_nonce)| pub_nonce.clone())
            .collect();
        db.save_nonces(outpoint, &nonce_pairs).await.unwrap();
        db.save_agg_nonces(outpoint, &agg_nonces).await.unwrap();
        let res = db
            .save_sighashes_and_get_nonces(outpoint, index, &sighashes)
            .await
            .unwrap();
    }
}

#[cfg(poc)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseContent {
    inscribed_connector_tree_preimages: Vec<Vec<PreimageType>>,
    connector_tree_hashes: Vec<HashTree>,
    claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    inscription_txs: Vec<InscriptionTxs>,
    deposit_txs: Vec<(Txid, TxOut)>,
    withdrawals_merkle_tree: MerkleTree<WITHDRAWAL_MERKLE_TREE_DEPTH>,
    withdrawals_payment_txids: Vec<Vec<WithdrawalPayment>>,
    connector_tree_utxos: Vec<ConnectorUTXOTree>,
    start_block_height: u64,
    period_relative_block_heights: Vec<u32>,
}
#[cfg(poc)]
impl DatabaseContent {
    pub fn _new() -> Self {
        Self {
            inscribed_connector_tree_preimages: Vec::new(),
            withdrawals_merkle_tree: MerkleTree::new(),
            withdrawals_payment_txids: Vec::new(),
            inscription_txs: Vec::new(),
            deposit_txs: Vec::new(),
            connector_tree_hashes: Vec::new(),
            claim_proof_merkle_trees: Vec::new(),
            connector_tree_utxos: Vec::new(),
            start_block_height: 0,
            period_relative_block_heights: Vec::new(),
        }
    }
}

#[cfg(poc)]
impl Database {
    pub async fn get_connector_tree_hash(
        &self,
        period: usize,
        level: usize,
        idx: usize,
    ) -> HashType {
        let content = self.read();

        // If database is empty, returns an empty array.
        match content.connector_tree_hashes.get(period) {
            Some(v) => match v.get(level) {
                Some(v) => match v.get(idx) {
                    Some(v) => *v,
                    _ => [0u8; 32],
                },
                _ => [0u8; 32],
            },
            _ => [0u8; 32],
        }
    }
    pub async fn set_connector_tree_hashes(&self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.connector_tree_hashes = connector_tree_hashes;
        self.write(content);
    }

    pub async fn get_claim_proof_merkle_tree(
        &self,
        period: usize,
    ) -> MerkleTree<CLAIM_MERKLE_TREE_DEPTH> {
        let content = self.read();

        match content.claim_proof_merkle_trees.get(period) {
            Some(p) => p.clone(),
            _ => MerkleTree::new(),
        }
    }
    pub async fn set_claim_proof_merkle_trees(
        &self,
        claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    ) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.claim_proof_merkle_trees = claim_proof_merkle_trees;
        self.write(content);
    }

    pub async fn get_inscription_txs(&self) -> Vec<InscriptionTxs> {
        let content = self.read();
        content.inscription_txs.clone()
    }
    pub async fn get_inscription_txs_len(&self) -> usize {
        let content = self.read();
        content.inscription_txs.len()
    }
    pub async fn add_to_inscription_txs(&self, inscription_txs: InscriptionTxs) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.inscription_txs.push(inscription_txs);
        self.write(content);
    }

    pub async fn get_deposit_txs(&self) -> Vec<(Txid, TxOut)> {
        let content = self.read();
        content.deposit_txs.clone()
    }

    pub async fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        let content = self.read();
        content.withdrawals_merkle_tree.index
    }
    pub async fn add_to_withdrawals_merkle_tree(&self, hash: HashType) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.withdrawals_merkle_tree.add(hash);
        self.write(content);
    }

    pub async fn get_withdrawals_payment_for_period(
        &self,
        period: usize,
    ) -> Vec<WithdrawalPayment> {
        let content = self.read();
        content.withdrawals_payment_txids[period].clone()
    }
    pub async fn add_to_withdrawals_payment_txids(
        &self,
        period: usize,
        withdrawal_payment: WithdrawalPayment,
    ) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        while period >= content.withdrawals_payment_txids.len() {
            content.withdrawals_payment_txids.push(Vec::new());
        }
        content.withdrawals_payment_txids[period].push(withdrawal_payment);
        self.write(content);
    }

    pub async fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorUTXOTree {
        let content = self.read();
        content.connector_tree_utxos[idx].clone()
    }
    pub async fn set_connector_tree_utxos(&self, connector_tree_utxos: Vec<ConnectorUTXOTree>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.connector_tree_utxos = connector_tree_utxos;
        self.write(content);
    }

    pub async fn get_start_block_height(&self) -> u64 {
        let content = self.read();
        content.start_block_height
    }
    pub async fn set_start_block_height(&self, start_block_height: u64) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.start_block_height = start_block_height;
        self.write(content);
    }

    pub async fn get_period_relative_block_heights(&self) -> Vec<u32> {
        let content = self.read();
        content.period_relative_block_heights.clone()
    }
    pub async fn set_period_relative_block_heights(&self, period_relative_block_heights: Vec<u32>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.period_relative_block_heights = period_relative_block_heights;
        self.write(content);
    }

    pub async fn get_inscribed_preimages(&self, period: usize) -> Vec<PreimageType> {
        let content = self.read();

        match content.inscribed_connector_tree_preimages.get(period) {
            Some(p) => p.clone(),
            _ => vec![[0u8; 32]],
        }
    }
    pub async fn add_inscribed_preimages(&self, period: usize, preimages: Vec<PreimageType>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        while period >= content.inscribed_connector_tree_preimages.len() {
            content.inscribed_connector_tree_preimages.push(Vec::new());
        }
        content.inscribed_connector_tree_preimages[period] = preimages;
        self.write(content);
    }
}

#[cfg(poc)]
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn deposit_tx() {
        let config = test_common::get_test_config("test_config.toml".to_string()).unwrap();
        let database = Database::new(config).await.unwrap();

        let prev_idx = database.get_next_deposit_index().await.unwrap();

        let mut rng = rand::thread_rng();
        let mut arr = [0; 32];
        for i in 0..32 {
            arr[i] = rng.gen();
        }
        let txid = Txid::from_byte_array(arr);

        database.insert_move_txid(txid).await.unwrap();

        let next_idx = database.get_next_deposit_index().await.unwrap();

        assert_eq!(prev_idx + 1, next_idx);

        let read_txid = database.get_deposit_tx(next_idx).await.unwrap();

        assert_eq!(read_txid, txid);
    }

    #[tokio::test]
    async fn connector_tree_hash() {
        let config = test_common::get_test_config("test_config.toml".to_string()).unwrap();
        let database = Database::new(config).await.unwrap();

        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data = [0x45u8; 32];
        let mock_array: Vec<Vec<Vec<HashType>>> = vec![vec![vec![mock_data]]];

        assert_ne!(database.get_connector_tree_hash(0, 0, 0).await, mock_data);

        database.set_connector_tree_hashes(mock_array).await;
        assert_eq!(database.get_connector_tree_hash(0, 0, 0).await, mock_data);
    }

    #[tokio::test]
    async fn claim_proof_merkle_tree() {
        let config = test_common::get_test_config("test_config.toml".to_string()).unwrap();
        let database = Database::new(config).await.unwrap();
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mut mock_data: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>> = vec![MerkleTree::new()];
        mock_data[0].add([0x45u8; 32]);

        assert_ne!(
            database.get_claim_proof_merkle_tree(0).await,
            mock_data[0].clone()
        );

        database
            .set_claim_proof_merkle_trees(mock_data.clone())
            .await;
        assert_eq!(database.get_claim_proof_merkle_tree(0).await, mock_data[0]);
    }

    #[tokio::test]
    async fn withdrawals_merkle_tree() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: HashType = [0x45u8; 32];

        assert_eq!(database.get_withdrawals_merkle_tree_index().await, 0);

        database
            .add_to_withdrawals_merkle_tree(mock_data.clone())
            .await;
        assert_eq!(database.get_withdrawals_merkle_tree_index().await, 1);
    }

    #[tokio::test]
    async fn start_block_height() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: u64 = 0x45;

        assert_eq!(database.get_start_block_height().await, 0);

        database.set_start_block_height(mock_data).await;
        assert_eq!(database.get_start_block_height().await, mock_data);
    }

    #[tokio::test]
    async fn period_relative_block_heights() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: u64 = 0x45;

        assert_eq!(database.get_start_block_height().await, 0);

        database.set_start_block_height(mock_data).await;
        assert_eq!(database.get_start_block_height().await, mock_data);
    }

    #[tokio::test]
    async fn inscribed_preimages() {
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: Vec<PreimageType> = vec![[0x45u8; 32]];

        assert_ne!(database.get_inscribed_preimages(0).await, mock_data);

        database.add_inscribed_preimages(0, mock_data.clone()).await;
        assert_eq!(database.get_inscribed_preimages(0).await, mock_data);

        // Clean things up.
        match fs::remove_file(DB_FILE_PATH) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}
