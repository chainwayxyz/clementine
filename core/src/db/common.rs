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

/// Main database struct that holds all the information of the database.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Database {
    pub content: DatabaseContent,
    pub dbms: TextDatabase,
}

/// First pack of implementation of `Database`. This pack includes general
/// functions for accessing the database.
impl Database {
    pub fn new() -> Self {
        Self {
            content: DatabaseContent::new(),
            dbms: TextDatabase::new(TEXT_DATABASE.into()),
        }
    }

    /// Calls actual database read function and writes it's contents to memory.
    fn read(&mut self) {
        match self.dbms.read() {
            Ok(c) => self.content = c,
            Err(e) => panic!("{}", e),
        }
    }

    /// Calls actual database write function and writes input data to database.
    fn write(&self) {
        match self.dbms.write(self.clone()) {
            Ok(_) => return,
            Err(e) => panic!("{}", e),
        }
    }
}

/// Tests for first pack of `Database`.
#[cfg(test)]
mod tests {
    use std::fs;
    use super::{Database, DatabaseContent};
    use crate::{constants::TEXT_DATABASE, db::text::TextDatabase};

    /// Tests if running `new()` function returns an empty struct.
    #[test]
    fn new() {
        let database = Database::new();
        assert_eq!(
            database,
            Database {
                content: DatabaseContent::new(),
                dbms: TextDatabase::new(TEXT_DATABASE.into()),
            }
        )
    }

    /// Writes mock data to database, then reads it. Compares if input equals
    /// output. This test is a bit redundant if it is done in actual database
    /// module.
    #[test]
    fn write_read() {
        // Create mock database and add mock data.
        let mut initial = Database::new();
        initial.add_to_withdrawals_merkle_tree([0x0F; 32]);

        // Commit changes to database.
        initial.write();

        // Check if comparison is not 
        let mut expected = Database::new();
        assert_ne!(initial, expected);

        expected.read();
        assert_eq!(initial, expected);

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}

/// Second implemantation pack of `Database`. This pack includes data
/// manupulation functions. They use first pack to access database.
impl Database {
    pub fn get_connector_tree_hash(&mut self, period: usize, level: usize, idx: usize) -> HashType {
        self.read();
        self.content.connector_tree_hashes[period][level][idx]
    }

    pub fn set_connector_tree_hashes(&mut self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>) {
        self.read();
        self.content.connector_tree_hashes = connector_tree_hashes;
        self.write();
    }

    pub fn set_claim_proof_merkle_trees(
        &mut self,
        claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    ) {
        self.content.claim_proof_merkle_trees = claim_proof_merkle_trees;
    }

    pub fn get_claim_proof_merkle_tree(
        &self,
        period: usize,
    ) -> MerkleTree<CLAIM_MERKLE_TREE_DEPTH> {
        self.content.claim_proof_merkle_trees[period].clone()
    }

    pub fn get_inscription_txs_len(&self) -> usize {
        self.content.inscription_txs.len()
    }

    pub fn add_to_inscription_txs(&mut self, inscription_txs: InscriptionTxs) {
        self.content.inscription_txs.push(inscription_txs);
    }

    pub fn get_inscription_txs(&self) -> Vec<InscriptionTxs> {
        self.content.inscription_txs.clone()
    }

    pub fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        self.content.withdrawals_merkle_tree.index
    }

    pub fn add_to_withdrawals_merkle_tree(&mut self, hash: HashType) {
        self.content.withdrawals_merkle_tree.add(hash);
    }

    pub fn add_to_withdrawals_payment_txids(
        &mut self,
        period: usize,
        withdrawal_payment: WithdrawalPayment,
    ) {
        while period >= self.content.withdrawals_payment_txids.len() {
            self.content.withdrawals_payment_txids.push(Vec::new());
        }
        self.content.withdrawals_payment_txids[period].push(withdrawal_payment);
    }

    pub fn get_withdrawals_payment_for_period(&self, period: usize) -> Vec<WithdrawalPayment> {
        self.content.withdrawals_payment_txids[period].clone()
    }

    pub fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorUTXOTree {
        self.content.connector_tree_utxos[idx].clone()
    }

    pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorUTXOTree>) {
        self.content.connector_tree_utxos = connector_tree_utxos;
    }

    pub fn get_start_block_height(&self) -> u64 {
        self.content.start_block_height
    }

    pub fn set_start_block_height(&mut self, start_block_height: u64) {
        self.content.start_block_height = start_block_height;
    }

    pub fn set_period_relative_block_heights(&mut self, period_relative_block_heights: Vec<u32>) {
        self.content.period_relative_block_heights = period_relative_block_heights;
    }
    pub fn get_period_relative_block_heights(&self) -> Vec<u32> {
        self.content.period_relative_block_heights.clone()
    }

    pub fn add_inscribed_preimages(&mut self, period: usize, preimages: Vec<PreimageType>) {
        while period >= self.content.inscribed_connector_tree_preimages.len() {
            self.content
                .inscribed_connector_tree_preimages
                .push(Vec::new());
        }
        self.content.inscribed_connector_tree_preimages[period] = preimages;
    }
    pub fn get_inscribed_preimages(&self, period: usize) -> Vec<PreimageType> {
        self.content.inscribed_connector_tree_preimages[period].clone()
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
