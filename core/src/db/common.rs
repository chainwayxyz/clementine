//! # Common Database Operations
//!
//! Common database operations for both operator and verifier.

use super::text::TextDatabase;
use crate::{
    constants::TEXT_DATABASE, merkle::MerkleTree, ConnectorUTXOTree, HashTree, InscriptionTxs,
    WithdrawalPayment,
};
use clementine_circuits::{
    constants::{CLAIM_MERKLE_TREE_DEPTH, WITHDRAWAL_MERKLE_TREE_DEPTH},
    HashType, PreimageType,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Main database struct that holds all the information of the database.
#[derive(Clone, Debug)]
pub struct Database {
    pub dbms: TextDatabase,
    pub lock: Arc<Mutex<usize>>,
}

/// First pack of implementation for the `Database`. This pack includes general
/// functions for accessing the database.
impl Database {
    pub fn new() -> Self {
        Self {
            dbms: TextDatabase::new(TEXT_DATABASE.into()),
            lock: Arc::new(Mutex::new(0)),
        }
    }

    /// Calls actual database read function and writes it's contents to memory.
    fn read(&self) -> DatabaseContent {
        match self.dbms.read() {
            Ok(c) => c,
            Err(_) => DatabaseContent::new(),
        }
    }

    /// Calls actual database write function and writes input data to database.
    fn write(&self, content: DatabaseContent) {
        match self.dbms.write(content) {
            Ok(_) => return,
            Err(e) => panic!("Writing to database: {}", e),
        }
    }
}

/// Second implementation pack of `Database`. This pack includes data
/// manupulation functions. They use first pack of functions to access database.
impl Database {
    pub fn get_connector_tree_hash(&self, period: usize, level: usize, idx: usize) -> HashType {
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
    pub fn set_connector_tree_hashes(&self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.connector_tree_hashes = connector_tree_hashes;
        self.write(content);
    }

    pub fn get_claim_proof_merkle_tree(
        &self,
        period: usize,
    ) -> MerkleTree<CLAIM_MERKLE_TREE_DEPTH> {
        let content = self.read();
        content.claim_proof_merkle_trees[period].clone()
    }
    pub fn set_claim_proof_merkle_trees(
        &self,
        claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    ) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.claim_proof_merkle_trees = claim_proof_merkle_trees;
        self.write(content);
    }

    pub fn get_inscription_txs(&self) -> Vec<InscriptionTxs> {
        let content = self.read();
        content.inscription_txs.clone()
    }
    pub fn get_inscription_txs_len(&self) -> usize {
        let content = self.read();
        content.inscription_txs.len()
    }
    pub fn add_to_inscription_txs(&self, inscription_txs: InscriptionTxs) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.inscription_txs.push(inscription_txs);
        self.write(content);
    }

    pub fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        let content = self.read();
        content.withdrawals_merkle_tree.index
    }
    pub fn add_to_withdrawals_merkle_tree(&self, hash: HashType) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.withdrawals_merkle_tree.add(hash);
        self.write(content);
    }

    pub fn get_withdrawals_payment_for_period(&self, period: usize) -> Vec<WithdrawalPayment> {
        let content = self.read();
        content.withdrawals_payment_txids[period].clone()
    }
    pub fn add_to_withdrawals_payment_txids(
        &self,
        period: usize,
        withdrawal_payment: WithdrawalPayment,
    ) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        while period >= content.withdrawals_payment_txids.len() {
            content.withdrawals_payment_txids.push(Vec::new());
        }
        content.withdrawals_payment_txids[period].push(withdrawal_payment);
        self.write(content);
    }

    pub fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorUTXOTree {
        let content = self.read();
        content.connector_tree_utxos[idx].clone()
    }
    pub fn set_connector_tree_utxos(&self, connector_tree_utxos: Vec<ConnectorUTXOTree>) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.connector_tree_utxos = connector_tree_utxos;
        self.write(content);
    }

    pub fn get_start_block_height(&self) -> u64 {
        let content = self.read();
        content.start_block_height
    }
    pub fn set_start_block_height(&self, start_block_height: u64) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.start_block_height = start_block_height;
        self.write(content);
    }

    pub fn get_period_relative_block_heights(&self) -> Vec<u32> {
        let content = self.read();
        content.period_relative_block_heights.clone()
    }
    pub fn set_period_relative_block_heights(&self, period_relative_block_heights: Vec<u32>) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        content.period_relative_block_heights = period_relative_block_heights;
        self.write(content);
    }

    pub fn get_inscribed_preimages(&self, period: usize) -> Vec<PreimageType> {
        let content = self.read();
        content.inscribed_connector_tree_preimages[period].clone()
    }
    pub fn add_inscribed_preimages(&self, period: usize, preimages: Vec<PreimageType>) {
        // let _guard = self.lock.lock().unwrap();
        let mut content = self.read();
        while period >= content.inscribed_connector_tree_preimages.len() {
            content.inscribed_connector_tree_preimages.push(Vec::new());
        }
        content.inscribed_connector_tree_preimages[period] = preimages;
        self.write(content);
    }
}

/// Actual information that database will hold. This information is not directly
/// accessible for an outsider; It should be updated and used by a database
/// organizer. Therefore, it is internal use only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseContent {
    inscribed_connector_tree_preimages: Vec<Vec<PreimageType>>,
    connector_tree_hashes: Vec<HashTree>,
    claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    inscription_txs: Vec<InscriptionTxs>,
    withdrawals_merkle_tree: MerkleTree<WITHDRAWAL_MERKLE_TREE_DEPTH>,
    withdrawals_payment_txids: Vec<Vec<WithdrawalPayment>>,
    connector_tree_utxos: Vec<ConnectorUTXOTree>,
    start_block_height: u64,
    period_relative_block_heights: Vec<u32>,
}
impl DatabaseContent {
    pub fn new() -> Self {
        Self {
            inscribed_connector_tree_preimages: Vec::new(),
            withdrawals_merkle_tree: MerkleTree::new(),
            withdrawals_payment_txids: Vec::new(),
            inscription_txs: Vec::new(),
            connector_tree_hashes: Vec::new(),
            claim_proof_merkle_trees: Vec::new(),
            connector_tree_utxos: Vec::new(),
            start_block_height: 0,
            period_relative_block_heights: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use clementine_circuits::HashType;

    use super::Database;
    use crate::{constants::TEXT_DATABASE, db::text::TextDatabase};
    use std::{fs, vec};

    /// Tests if running `new()` function returns an empty struct.
    #[test]
    fn new() {
        let database = Database::new();

        // Some of the members of the `Database` struct are not comparable. So,
        // we need to do this one by one.
        assert_eq!(database.dbms, TextDatabase::new(TEXT_DATABASE.into()));
    }

    /// Writes mock data to database, then reads it. Compares if input equals
    /// output. This test is a bit redundant if it is done in actual database
    /// module.
    #[test]
    fn write_read() {
        // Create mock database and add mock data to database.
        let db = Database::new();

        // Add random datas to db.

        db.add_to_withdrawals_merkle_tree([0x0F; 32]);
        let ret = db.get_withdrawals_merkle_tree_index();
        assert_eq!(ret, 1);

        db.add_to_withdrawals_merkle_tree([0x1F; 32]);
        let ret = db.get_withdrawals_merkle_tree_index();
        assert_eq!(ret, 2);

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn connector_tree_hash() {
        let database = Database::new();

        let mock_data = [0x45; 32];
        let mock_array: Vec<Vec<Vec<HashType>>> = vec![vec![vec![mock_data]]];

        assert_ne!(database.get_connector_tree_hash(0, 0, 0), mock_data);

        database.set_connector_tree_hashes(mock_array);
        assert_eq!(database.get_connector_tree_hash(0, 0, 0), mock_data);

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}
