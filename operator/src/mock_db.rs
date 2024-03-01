use bitcoin::Txid;

use crate::{
    config::DEPTH,
    constant::{ConnectorTreeUTXOs, HashType, InscriptionTxs, PreimageType},
    merkle::MerkleTree,
    operator::OperatorClaimSigs,
};

#[derive(Debug, Clone)]
pub struct OperatorMockDB {
    deposit_take_sigs: Vec<OperatorClaimSigs>,
    connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    connector_tree_hashes: Vec<Vec<Vec<HashType>>>,
    inscription_txs: Vec<InscriptionTxs>,
    // deposit_merkle_tree: MerkleTree<DEPTH>,
    withdrawals_merkle_tree: MerkleTree<DEPTH>,
    withdrawals_payment_txids: Vec<Txid>,
    connector_tree_utxos: Vec<ConnectorTreeUTXOs>,
    // deposit_utxos: Vec<OutPoint>,
    // move_utxos: Vec<OutPoint>,
}

impl OperatorMockDB {
    pub fn new() -> Self {
        Self {
            deposit_take_sigs: Vec::new(),
            // deposit_merkle_tree: MerkleTree::new(),
            withdrawals_merkle_tree: MerkleTree::new(),
            withdrawals_payment_txids: Vec::new(),
            inscription_txs: Vec::new(),
            connector_tree_preimages: Vec::new(),
            connector_tree_hashes: Vec::new(),
            // deposit_utxos: Vec::new(),
            // move_utxos: Vec::new(),
            connector_tree_utxos: Vec::new(),
        }
    }

    pub fn get_deposit_index(&self) -> usize {
        self.deposit_take_sigs.len()
    }

    // pub fn get_deposit_take_sigs(&self) -> Vec<OperatorClaimSigs> {
    //     self.deposit_take_sigs.clone()
    // }

    pub fn add_deposit_take_sigs(&mut self, deposit_take_sigs: OperatorClaimSigs) {
        self.deposit_take_sigs.push(deposit_take_sigs);
    }

    pub fn get_connector_tree_preimages_level(
        &self,
        period: usize,
        level: usize,
    ) -> Vec<PreimageType> {
        self.connector_tree_preimages[period][level].clone()
    }

    pub fn get_connector_tree_preimages(
        &self,
        period: usize,
        level: usize,
        idx: usize,
    ) -> PreimageType {
        self.connector_tree_preimages[period][level][idx].clone()
    }

    pub fn set_connector_tree_preimages(
        &mut self,
        connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    ) {
        self.connector_tree_preimages = connector_tree_preimages;
    }

    pub fn get_connector_tree_hash(&self, period: usize, level: usize, idx: usize) -> HashType {
        self.connector_tree_hashes[period][level][idx]
    }

    pub fn get_connector_tree_hashes(&self) -> Vec<Vec<Vec<HashType>>> {
        self.connector_tree_hashes.clone()
    }

    pub fn set_connector_tree_hashes(&mut self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>) {
        self.connector_tree_hashes = connector_tree_hashes;
    }

    pub fn get_inscription_txs_len(&self) -> usize {
        self.inscription_txs.len()
    }

    pub fn add_to_inscription_txs(&mut self, inscription_txs: InscriptionTxs) {
        self.inscription_txs.push(inscription_txs);
    }

    // pub fn get_deposit_merkle_tree(&self) -> MerkleTree<DEPTH> {
    //     self.deposit_merkle_tree.clone()
    // }

    // pub fn set_deposit_merkle_tree(&mut self, deposit_merkle_tree: MerkleTree<DEPTH>) {
    //     self.deposit_merkle_tree = deposit_merkle_tree;
    // }

    pub fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        self.withdrawals_merkle_tree.index
    }

    pub fn add_to_withdrawals_merkle_tree(&mut self, hash: HashType) {
        self.withdrawals_merkle_tree.add(hash);
    }

    // pub fn get_withdrawals_payment_txids(&self) -> Vec<Txid> {
    //     self.withdrawals_payment_txids.clone()
    // }

    pub fn add_to_withdrawals_payment_txids(&mut self, txid: Txid) {
        self.withdrawals_payment_txids.push(txid);
    }

    pub fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorTreeUTXOs {
        self.connector_tree_utxos[idx].clone()
    }

    pub fn get_connector_tree_utxos(&self) -> Vec<ConnectorTreeUTXOs> {
        self.connector_tree_utxos.clone()
    }

    pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorTreeUTXOs>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }

    // pub fn get_deposit_utxos(&self) -> Vec<OutPoint> {
    //     self.deposit_utxos.clone()
    // }

    // pub fn add_deposit_utxos(&mut self, deposit_utxos: OutPoint) {
    //     self.deposit_utxos.push(deposit_utxos);
    // }

    // pub fn get_move_utxos(&self) -> Vec<OutPoint> {
    //     self.move_utxos.clone()
    // }

    // pub fn add_move_utxos(&mut self, move_utxos: OutPoint) {
    //     self.move_utxos.push(move_utxos);
    // }
}
