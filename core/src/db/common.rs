//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.
//!
//! ## Testing
//!
//! For testing, user can supply out-of-source-tree configuration file with
//! `TEST_CONFIG` environment variable (`core/src/test_common.rs`).
//!
//! Tests that requires a proper PostgreSQL host configuration flagged with
//! `ignore`. They can be run if configuration is OK with `--include-ignored`
//! `cargo test` flag.

use crate::EVMAddress;
use crate::{config::BridgeConfig, errors::BridgeError};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, Txid};
use sqlx::Row;
use sqlx::{Pool, Postgres};
use std::str::FromStr;

/// Main database struct that holds all the information of the database.
#[derive(Clone, Debug)]
pub struct Database {
    connection: Pool<Postgres>,
}

impl Database {
    /// Creates a new `Database`. Then tries to establish a connection to
    /// PostgreSQL.
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

    /// Returns an object for database transaction. This must be handled where
    /// it is called. If not, database operations that executed after this will
    /// get dropped.
    pub async fn begin_transaction(
        &self,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
        match self.connection.begin().await {
            Ok(t) => Ok(t),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    pub async fn get_new_deposit_transaction(
        &self,
    ) -> Result<(OutPoint, Address<NetworkUnchecked>, EVMAddress), BridgeError> {
        // TODO: This table needs a specifier like timestamp or an id to order stuff.
        match sqlx::query("SELECT * FROM new_deposit_requests;")
            .fetch_one(&self.connection)
            .await
        {
            Ok(qr) => {
                let start_utxo = OutPoint::from_str(&qr.get::<String, _>(0));
                let start_utxo = match start_utxo {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(BridgeError::DatabaseError(sqlx::Error::AnyDriverError(
                            Box::new(e),
                        )))
                    }
                };

                let recovery_taproot_address: Result<Address<NetworkUnchecked>, _> = serde_json::from_str(qr.get::<&str, _>(1));
                let recovery_taproot_address = match recovery_taproot_address {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(BridgeError::DatabaseError(sqlx::Error::AnyDriverError(
                            Box::new(e),
                        )))
                    }
                };

                let evm_address: Result<EVMAddress, serde_json::Error> =
                    serde_json::from_str(qr.get::<&str, _>(2));
                let evm_address = match evm_address {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(BridgeError::DatabaseError(sqlx::Error::AnyDriverError(
                            Box::new(e),
                        )))
                    }
                };

                Ok((start_utxo, recovery_taproot_address, evm_address))
            }
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }
    pub async fn add_new_deposit_transaction(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<(), BridgeError> {
        // TODO: These probably won't panic. But we should handle these
        // properly regardless, in the future.
        if let Err(e) = sqlx::query("INSERT INTO new_deposit_requests VALUES ($1, $2, $3);")
            .bind(start_utxo.to_string())
            .bind(serde_json::to_string(&recovery_taproot_address).unwrap())
            .bind(serde_json::to_string(&evm_address).unwrap())
            .fetch_all(&self.connection)
            .await
        {
            return Err(BridgeError::DatabaseError(e));
        };

        Ok(())
    }

    pub async fn get_deposit_tx(&self, idx: usize) -> Result<Txid, BridgeError> {
        let qr = sqlx::query("SELECT move_txid FROM deposit_move_txs WHERE id = $1;")
            .bind(idx as i64)
            .fetch_one(&self.connection)
            .await;
        tracing::debug!("QR: GETTING QR for :{:?}", idx);
        let qr = match qr {
            Ok(c) => c,
            Err(e) => return Err(BridgeError::DatabaseError(e)),
        };

        // tracing::debug!("QR: {:?}", qr.get::<String, _>(0));
        match Txid::from_str(&qr.get::<String, _>(0)) {
            Ok(c) => Ok(c),
            Err(e) => {
                tracing::error!("Error: {:?}", e);
                Err(BridgeError::DatabaseError(sqlx::Error::RowNotFound))
            } // TODO: Is this correct?
        }
    }

    pub async fn get_next_deposit_index(&self) -> Result<usize, BridgeError> {
        match sqlx::query("SELECT COUNT(*) FROM deposit_move_txs;")
            .fetch_one(&self.connection)
            .await
        {
            Ok(qr) => Ok(qr.get::<i64, _>(0) as usize),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }
    pub async fn insert_move_txid(&self, move_txid: Txid) -> Result<(), BridgeError> {
        if let Err(e) = sqlx::query("INSERT INTO deposit_move_txs (move_txid) VALUES ($1);")
            .bind(move_txid.to_string())
            .fetch_all(&self.connection)
            .await
        {
            return Err(BridgeError::DatabaseError(e));
        };

        Ok(())
    }

    pub async fn insert_move_txid_with_id(
        &self,
        id: usize,
        move_txid: Txid,
    ) -> Result<(), BridgeError> {
        if let Err(e) = sqlx::query("INSERT INTO deposit_move_txs VALUES ($1, $2);")
            .bind(id as i64)
            .bind(move_txid.to_string())
            .fetch_all(&self.connection)
            .await
        {
            return Err(BridgeError::DatabaseError(e));
        };

        Ok(())
    }

    #[cfg(poc)]
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
    #[cfg(poc)]
    pub async fn set_connector_tree_hashes(&self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.connector_tree_hashes = connector_tree_hashes;
        self.write(content);
    }

    #[cfg(poc)]
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
    #[cfg(poc)]
    pub async fn set_claim_proof_merkle_trees(
        &self,
        claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    ) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.claim_proof_merkle_trees = claim_proof_merkle_trees;
        self.write(content);
    }

    #[cfg(poc)]
    pub async fn get_inscription_txs(&self) -> Vec<InscriptionTxs> {
        let content = self.read();
        content.inscription_txs.clone()
    }
    #[cfg(poc)]
    pub async fn get_inscription_txs_len(&self) -> usize {
        let content = self.read();
        content.inscription_txs.len()
    }
    #[cfg(poc)]
    pub async fn add_to_inscription_txs(&self, inscription_txs: InscriptionTxs) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.inscription_txs.push(inscription_txs);
        self.write(content);
    }

    #[cfg(poc)]
    pub async fn get_deposit_txs(&self) -> Vec<(Txid, TxOut)> {
        let content = self.read();
        content.deposit_txs.clone()
    }

    #[cfg(poc)]
    pub async fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        let content = self.read();
        content.withdrawals_merkle_tree.index
    }
    #[cfg(poc)]
    pub async fn add_to_withdrawals_merkle_tree(&self, hash: HashType) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.withdrawals_merkle_tree.add(hash);
        self.write(content);
    }

    #[cfg(poc)]
    pub async fn get_withdrawals_payment_for_period(
        &self,
        period: usize,
    ) -> Vec<WithdrawalPayment> {
        let content = self.read();
        content.withdrawals_payment_txids[period].clone()
    }
    #[cfg(poc)]
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

    #[cfg(poc)]
    pub async fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorUTXOTree {
        let content = self.read();
        content.connector_tree_utxos[idx].clone()
    }
    #[cfg(poc)]
    pub async fn set_connector_tree_utxos(&self, connector_tree_utxos: Vec<ConnectorUTXOTree>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.connector_tree_utxos = connector_tree_utxos;
        self.write(content);
    }

    #[cfg(poc)]
    pub async fn get_start_block_height(&self) -> u64 {
        let content = self.read();
        content.start_block_height
    }
    #[cfg(poc)]
    pub async fn set_start_block_height(&self, start_block_height: u64) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.start_block_height = start_block_height;
        self.write(content);
    }

    #[cfg(poc)]
    pub async fn get_period_relative_block_heights(&self) -> Vec<u32> {
        let content = self.read();
        content.period_relative_block_heights.clone()
    }
    #[cfg(poc)]
    pub async fn set_period_relative_block_heights(&self, period_relative_block_heights: Vec<u32>) {
        let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.period_relative_block_heights = period_relative_block_heights;
        self.write(content);
    }

    #[cfg(poc)]
    pub async fn get_inscribed_preimages(&self, period: usize) -> Vec<PreimageType> {
        let content = self.read();

        match content.inscribed_connector_tree_preimages.get(period) {
            Some(p) => p.clone(),
            _ => vec![[0u8; 32]],
        }
    }
    #[cfg(poc)]
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

/// These tests not just aims to show correctness of the implementation: They
/// are here to show doing asynchronous operations over db is possible and data
/// won't get corrupted while doing so. Although db functions guarantee there
/// won't be a data race once a function is called, they won't guarantee data
/// will stay same between two db function calls. Therefore we need to da a
/// manual synchronization between tests too.
///
/// Currently, some tests for some functions are absent because of the complex
/// parameters: They are hard to mock.
#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{config::BridgeConfig, test_common, EVMAddress};
    use bitcoin::{hashes::Hash, Address, OutPoint, Txid, XOnlyPublicKey};
    use secp256k1::{
        rand::{self, Rng},
        Secp256k1,
    };

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
    #[ignore]
    async fn valid_connection() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();

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
    async fn new_deposit_transaction() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();
        let database = Database::new(config.clone()).await.unwrap();
        let secp = Secp256k1::new();
        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();
        let address = Address::p2tr(&secp, xonly_public_key, None, config.network);

        let prev_start_utxo = OutPoint::null();
        let prev_recovery_taproot_address = address.as_unchecked().clone();
        let prev_read_evm_address = EVMAddress([0u8; 20]);
        database
            .add_new_deposit_transaction(
                prev_start_utxo,
                prev_recovery_taproot_address.clone(),
                prev_read_evm_address,
            )
            .await
            .unwrap();

        let (read_start_utxo, read_recovery_taproot_address, read_evm_address) = database.get_new_deposit_transaction().await.unwrap();

        assert_eq!((prev_start_utxo, prev_recovery_taproot_address, prev_read_evm_address), (read_start_utxo, read_recovery_taproot_address, read_evm_address));
    }

    #[tokio::test]
    async fn deposit_tx() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();
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

    #[cfg(poc)]
    #[tokio::test]
    async fn connector_tree_hash() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();
        let database = Database::new(config).await.unwrap();

        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data = [0x45u8; 32];
        let mock_array: Vec<Vec<Vec<HashType>>> = vec![vec![vec![mock_data]]];

        assert_ne!(database.get_connector_tree_hash(0, 0, 0).await, mock_data);

        database.set_connector_tree_hashes(mock_array).await;
        assert_eq!(database.get_connector_tree_hash(0, 0, 0).await, mock_data);
    }

    #[cfg(poc)]
    #[tokio::test]
    async fn claim_proof_merkle_tree() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();
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

    #[cfg(poc)]
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

    #[cfg(poc)]
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

    #[cfg(poc)]
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

    #[cfg(poc)]
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

/// Actual information that database will hold. This information is not directly
/// accessible for an outsider; It should be updated and used by a database
/// organizer. Therefore, it is internal use only.
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
