//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.

use crate::EVMAddress;
use crate::{config::BridgeConfig, errors::BridgeError};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, Txid};
use sqlx::{Pool, Postgres};
use std::fs;
use std::str::FromStr;

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

    pub async fn add_new_deposit_request(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(), BridgeError> {
        let start_utxo = start_utxo.to_string();
        let recovery_taproot_address = serde_json::to_string(&recovery_taproot_address)
            .unwrap()
            .trim_matches('"')
            .to_owned();
        let evm_address = serde_json::to_string(&evm_address)
            .unwrap()
            .trim_matches('"')
            .to_owned();

        sqlx::query("INSERT INTO new_deposit_requests (start_utxo, recovery_taproot_address, evm_address) VALUES ($1, $2, $3);")
            .bind(start_utxo)
            .bind(recovery_taproot_address)
            .bind(evm_address)
            .fetch_all(&self.connection)
            .await?;

        Ok(())
    }

    pub async fn get_deposit_tx(&self, idx: usize) -> Result<Txid, BridgeError> {
        let qr: (String,) = sqlx::query_as("SELECT move_txid FROM deposit_move_txs WHERE id = $1;")
            .bind(idx as i64)
            .fetch_one(&self.connection)
            .await?;

        match Txid::from_str(qr.0.as_str()) {
            Ok(c) => Ok(c),
            Err(e) => Err(BridgeError::DatabaseError(sqlx::Error::Decode(Box::new(e)))),
        }
    }

    pub async fn get_next_deposit_index(&self) -> Result<usize, BridgeError> {
        let qr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM deposit_move_txs;")
            .fetch_one(&self.connection)
            .await?;

        Ok(qr.0 as usize)
    }

    pub async fn insert_move_txid(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        move_txid: Txid,
    ) -> Result<(), BridgeError> {
        sqlx::query("INSERT INTO deposit_move_txs (start_utxo, recovery_taproot_address, evm_address, move_txid) VALUES ($1, $2, $3, $4);")
            .bind(start_utxo.to_string())
            .bind(serde_json::to_string(&recovery_taproot_address).unwrap().trim_matches('"'))
            .bind(serde_json::to_string(&evm_address).unwrap().trim_matches('"'))
            .bind(move_txid.to_string())
            .fetch_all(&self.connection)
            .await?;

        Ok(())
    }

    pub async fn get_move_txid(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Txid, BridgeError> {
        let qr: (String,) = sqlx::query_as("SELECT (move_txid) FROM deposit_move_txs WHERE start_utxo = $1 AND recovery_taproot_address = $2 AND evm_address = $3;")
            .bind(start_utxo.to_string())
            .bind(serde_json::to_string(&recovery_taproot_address).unwrap().trim_matches('"'))
            .bind(serde_json::to_string(&evm_address).unwrap().trim_matches('"'))
            .fetch_one(&self.connection)
            .await?;

        let move_txid = Txid::from_str(&qr.0).unwrap();
        Ok(move_txid)
    }

    pub async fn save_withdrawal_sig(
        &self,
        idx: usize,
        bridge_fund_txid: Txid,
        sig: secp256k1::schnorr::Signature,
    ) -> Result<(), BridgeError> {
        sqlx::query(
            "INSERT INTO withdrawal_sigs (idx, bridge_fund_txid, sig) VALUES ($1, $2, $3);",
        )
        .bind(idx as i64)
        .bind(bridge_fund_txid.to_string())
        .bind(sig.to_string())
        .fetch_all(&self.connection)
        .await?;

        Ok(())
    }

    pub async fn get_withdrawal_sig_by_idx(
        &self,
        idx: usize,
    ) -> Result<(Txid, secp256k1::schnorr::Signature), BridgeError> {
        let qr: (String, String) =
            sqlx::query_as("SELECT (bridge_fund_txid, sig) FROM withdrawal_sigs WHERE idx = $1;")
                .bind(idx as i64)
                .fetch_one(&self.connection)
                .await?;

        let bridge_fund_txid = Txid::from_str(&qr.0).unwrap();
        let sig = secp256k1::schnorr::Signature::from_str(&qr.1).unwrap();
        Ok((bridge_fund_txid, sig))
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{
        config::BridgeConfig, create_test_database, create_test_database_with_thread_name,
        mock::common, EVMAddress,
    };
    use bitcoin::{Address, OutPoint, XOnlyPublicKey};
    use secp256k1::Secp256k1;
    use std::thread;

    #[tokio::test]
    async fn invalid_connection() {
        let mut config = BridgeConfig::new();
        config.db_host = "nonexistinghost".to_string();
        config.db_name = "nonexistingpassword".to_string();
        config.db_user = "nonexistinguser".to_string();
        config.db_password = "nonexistingpassword".to_string();
        config.db_port = 123;

        match Database::new(config).await {
            Ok(_) => {
                assert!(false);
            }
            Err(e) => {
                println!("{}", e);
                assert!(true);
            }
        };
    }

    #[tokio::test]
    async fn valid_connection() {
        let config = common::get_test_config("test_config.toml").unwrap();

        match Database::new(config).await {
            Ok(_) => {
                assert!(true);
            }
            Err(e) => {
                eprintln!("{}", e);
                assert!(false);
            }
        };
    }

    #[tokio::test]
    async fn create_drop_database() {
        let handle = thread::current()
            .name()
            .unwrap()
            .split(":")
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
    async fn add_deposit_transaction() {
        let config = create_test_database_with_thread_name!("test_config.toml");
        let database = Database::new(config.clone()).await.unwrap();

        let secp = Secp256k1::new();
        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();
        let address = Address::p2tr(&secp, xonly_public_key, None, config.network);

        database
            .add_new_deposit_request(
                OutPoint::null(),
                address.as_unchecked().clone(),
                EVMAddress([0u8; 20]),
            )
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
