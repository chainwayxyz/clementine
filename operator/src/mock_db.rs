use std::collections::HashMap;

use bitcoin::{OutPoint, Txid};

use crate::{
    config::DEPTH,
    constant::{ConnectorTreeUTXOs, HashType, InscriptionTxs, PreimageType},
    merkle::MerkleTree,
    operator::{DepositPresigns, OperatorClaimSigs},
};

#[derive(Debug, Clone)]
pub struct OperatorMockDB {
    pub deposit_take_sigs: Vec<OperatorClaimSigs>,
    pub connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    pub connector_tree_hashes: Vec<Vec<Vec<HashType>>>,
    pub inscription_txs: Vec<InscriptionTxs>,
    pub deposit_presigns: HashMap<Txid, Vec<DepositPresigns>>,
    pub deposit_merkle_tree: MerkleTree<DEPTH>,
    pub withdrawals_merkle_tree: MerkleTree<DEPTH>,
    pub withdrawals_payment_txids: Vec<Txid>,
    pub connector_tree_utxos: Vec<ConnectorTreeUTXOs>,
    pub deposit_utxos: Vec<OutPoint>,
    pub move_utxos: Vec<OutPoint>,
}

impl OperatorMockDB {
    pub fn new() -> Self {
        Self {
            deposit_take_sigs: Vec::new(),
            deposit_presigns: HashMap::new(),
            deposit_merkle_tree: MerkleTree::new(),
            withdrawals_merkle_tree: MerkleTree::new(),
            withdrawals_payment_txids: Vec::new(),
            inscription_txs: Vec::new(),
            connector_tree_preimages: Vec::new(),
            connector_tree_hashes: Vec::new(),
            deposit_utxos: Vec::new(),
            move_utxos: Vec::new(),
            connector_tree_utxos: Vec::new(),
        }
    }
}
