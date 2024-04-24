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
use std::{
    io::{Error, ErrorKind},
    sync::{Arc, Mutex},
};

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
    fn read(&self) -> Result<DatabaseContent, Error> {
        match self.dbms.read() {
            Ok(c) => Ok(c),
            Err(e) => match e.kind() {
                // If database is not yet created, we should create now.
                ErrorKind::NotFound => Ok(DatabaseContent::new()),
                _ => return Err(e),
            },
        }
    }

    /// Calls actual database write function and writes input data to database.
    fn write(&self, content: DatabaseContent) -> Result<(), Error> {
        self.dbms.write(content)
    }
}

/// Second implementation pack of `Database`. This pack includes data
/// manupulation functions. They use first pack of functions to access database.
///
/// `Set` functions use a mutex to avoid data races while updating database. But
/// it is not guaranteed that calling `get` and `set` functions one by one won't
/// result on a data race. Users must do their own synchronization to avoid data
/// races.
impl Database {
    pub fn get_connector_tree_hash(
        &self,
        period: usize,
        level: usize,
        idx: usize,
    ) -> Result<HashType, Error> {
        let content = self.read()?;

        // If database is empty, returns an empty array.
        match content.connector_tree_hashes.get(period) {
            Some(v) => match v.get(level) {
                Some(v) => match v.get(idx) {
                    Some(v) => Ok(*v),
                    None => Err(Error::other("Index could not be found")),
                },
                None => Err(Error::other("Level could not be found")),
            },
            None => Err(Error::other("Period could not be found")),
        }
    }
    pub fn set_connector_tree_hashes(
        &self,
        connector_tree_hashes: Vec<Vec<Vec<HashType>>>,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.connector_tree_hashes = connector_tree_hashes;
        self.write(content)?;

        Ok(())
    }

    pub fn get_claim_proof_merkle_tree(
        &self,
        period: usize,
    ) -> Result<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>, Error> {
        let content = self.read()?;

        match content.claim_proof_merkle_trees.get(period) {
            Some(p) => Ok(p.clone()),
            None => Err(Error::other("Period could not be found")),
        }
    }
    pub fn set_claim_proof_merkle_trees(
        &self,
        claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.claim_proof_merkle_trees = claim_proof_merkle_trees;
        self.write(content)?;

        Ok(())
    }

    pub fn get_inscription_txs(&self) -> Result<Vec<InscriptionTxs>, Error> {
        let content = self.read()?;
        Ok(content.inscription_txs.clone())
    }
    pub fn get_inscription_txs_len(&self) -> Result<usize, Error> {
        let content = self.read()?;
        Ok(content.inscription_txs.len())
    }
    pub fn add_to_inscription_txs(&self, inscription_txs: InscriptionTxs) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.inscription_txs.push(inscription_txs);
        self.write(content)?;

        Ok(())
    }

    pub fn get_withdrawals_merkle_tree_index(&self) -> Result<u32, Error> {
        let content = self.read()?;
        Ok(content.withdrawals_merkle_tree.index)
    }
    pub fn add_to_withdrawals_merkle_tree(&self, hash: HashType) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.withdrawals_merkle_tree.add(hash);
        self.write(content)?;

        Ok(())
    }

    pub fn get_withdrawals_payment_for_period(
        &self,
        period: usize,
    ) -> Result<Vec<WithdrawalPayment>, Error> {
        let content = self.read()?;
        Ok(content.withdrawals_payment_txids[period].clone())
    }
    pub fn add_to_withdrawals_payment_txids(
        &self,
        period: usize,
        withdrawal_payment: WithdrawalPayment,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        while period >= content.withdrawals_payment_txids.len() {
            content.withdrawals_payment_txids.push(Vec::new());
        }
        content.withdrawals_payment_txids[period].push(withdrawal_payment);
        self.write(content)?;

        Ok(())
    }

    pub fn get_connector_tree_utxo(&self, idx: usize) -> Result<ConnectorUTXOTree, Error> {
        let content = self.read()?;
        Ok(content.connector_tree_utxos[idx].clone())
    }
    pub fn set_connector_tree_utxos(
        &self,
        connector_tree_utxos: Vec<ConnectorUTXOTree>,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.connector_tree_utxos = connector_tree_utxos;
        self.write(content)?;

        Ok(())
    }

    pub fn get_start_block_height(&self) -> Result<u64, Error> {
        let content = self.read()?;
        Ok(content.start_block_height)
    }
    pub fn set_start_block_height(&self, start_block_height: u64) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.start_block_height = start_block_height;
        self.write(content)?;

        Ok(())
    }

    pub fn get_period_relative_block_heights(&self) -> Result<Vec<u32>, Error> {
        let content = self.read()?;
        Ok(content.period_relative_block_heights.clone())
    }
    pub fn set_period_relative_block_heights(
        &self,
        period_relative_block_heights: Vec<u32>,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        content.period_relative_block_heights = period_relative_block_heights;
        self.write(content)?;

        Ok(())
    }

    pub fn get_inscribed_preimages(&self, period: usize) -> Result<Vec<PreimageType>, Error> {
        let content = self.read()?;

        match content.inscribed_connector_tree_preimages.get(period) {
            Some(p) => Ok(p.clone()),
            None => Err(Error::other("Period could not be found")),
        }
    }
    pub fn add_inscribed_preimages(
        &self,
        period: usize,
        preimages: Vec<PreimageType>,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap();

        let mut content = self.read()?;
        while period >= content.inscribed_connector_tree_preimages.len() {
            content.inscribed_connector_tree_preimages.push(Vec::new());
        }
        content.inscribed_connector_tree_preimages[period] = preimages;
        self.write(content)?;

        Ok(())
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
    use crate::{constants::TEXT_DATABASE, db::text::TextDatabase, merkle::MerkleTree};
    use clementine_circuits::{constants::*, HashType, PreimageType};
    use std::{
        fs,
        sync::{Arc, Mutex, Once},
        vec,
    };

    // `Database` manages syncronization. So, we need to operate on a common
    // struct in order to do asynchronous operations on the database. Because
    // of the structure of Rust tests, we need to these things to have a common
    // `Database` struct.
    static START: Once = Once::new();
    static mut DATABASE: Option<Database> = None;
    static mut LOCK: Option<Arc<Mutex<usize>>> = None;
    pub unsafe fn initialize() {
        START.call_once(|| {
            DATABASE = Some(Database::new());
            LOCK = Some(Arc::new(Mutex::new(0)));
        });
    }

    /// Tests if running `new()` function returns an empty struct.
    #[test]
    fn new() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        // Some of the members of the `Database` struct are not comparable. So,
        // we need to do this one by one.
        assert_eq!(database.dbms, TextDatabase::new(TEXT_DATABASE.into()));
    }

    /// Writes mock data to database, then reads it. Compares if input equals
    /// output. This test is a bit redundant if it is done in actual database
    /// module.
    #[test]
    fn write_read() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        // Add random datas to database.
        let current_idx = database.get_withdrawals_merkle_tree_index().unwrap();

        let _ = database.add_to_withdrawals_merkle_tree([0x45u8; 32]);
        let ret = database.get_withdrawals_merkle_tree_index().unwrap();
        assert_eq!(ret, current_idx + 1);

        let _ = database.add_to_withdrawals_merkle_tree([0x1Fu8; 32]);
        let ret = database.get_withdrawals_merkle_tree_index().unwrap();
        assert_eq!(ret, current_idx + 2);

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn connector_tree_hash() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data = [0x45u8; 32];
        let mock_array: Vec<Vec<Vec<HashType>>> = vec![vec![vec![mock_data]]];

        match database.get_connector_tree_hash(0, 0, 0) {
            Ok(r) => assert_ne!(r, mock_data),
            Err(_) => (),
        };

        let _ = database.set_connector_tree_hashes(mock_array);
        match database.get_connector_tree_hash(0, 0, 0) {
            Ok(r) => assert_eq!(r, mock_data),
            Err(e) => println!("{}", e),
        };

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn claim_proof_merkle_tree() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mut mock_data: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>> = vec![MerkleTree::new()];
        mock_data[0].add([0x45u8; 32]);

        match database.get_claim_proof_merkle_tree(0) {
            Ok(r) => assert_ne!(r, mock_data[0].clone()),
            Err(_) => (),
        };

        let _ = database.set_claim_proof_merkle_trees(mock_data.clone());
        match database.get_claim_proof_merkle_tree(0) {
            Ok(r) => assert_eq!(r, mock_data[0]),
            Err(_) => assert!(false),
        };

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn withdrawals_merkle_tree() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: HashType = [0x45u8; 32];

        match database.get_withdrawals_merkle_tree_index() {
            Ok(r) => assert_eq!(r, 0),
            Err(_) => assert!(false),
        };

        let _ = database.add_to_withdrawals_merkle_tree(mock_data.clone());
        match database.get_withdrawals_merkle_tree_index() {
            Ok(r) => assert_eq!(r, 1),
            Err(_) => assert!(false),
        };

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn start_block_height() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: u64 = 0x45;

        match database.get_start_block_height() {
            Ok(r) => assert_eq!(r, 0),
            Err(_) => assert!(false),
        };

        let _ = database.set_start_block_height(mock_data);
        match database.get_start_block_height() {
            Ok(r) => assert_eq!(r, mock_data),
            Err(_) => assert!(false),
        };

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn period_relative_block_heights() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data = vec![0x45];

        match database.get_period_relative_block_heights() {
            Ok(r) => assert_ne!(r, mock_data),
            Err(_) => (),
        };

        let _ = database.set_period_relative_block_heights(mock_data.clone());
        match database.get_period_relative_block_heights() {
            Ok(r) => assert_eq!(r, mock_data),
            Err(_) => assert!(false),
        };

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn inscribed_preimages() {
        let database = unsafe {
            initialize();
            DATABASE.clone().unwrap()
        };
        let lock = unsafe { LOCK.clone().unwrap() };
        let _guard = lock.lock().unwrap();

        let mock_data: Vec<PreimageType> = vec![[0x45u8; 32]];

        match database.get_inscribed_preimages(0) {
            Ok(r) => assert_ne!(r, mock_data),
            Err(_) => (),
        };

        let _ = database.add_inscribed_preimages(0, mock_data.clone());
        match database.get_inscribed_preimages(0) {
            Ok(r) => assert_eq!(r, mock_data),
            Err(_) => assert!(false),
        };

        // Clean things up.
        match fs::remove_file(TEXT_DATABASE) {
            Ok(_) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}
