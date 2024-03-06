use bitcoin::Txid;

use crate::{
    config::DEPTH,
    constant::{ConnectorTreeUTXOs, HashType, InscriptionTxs, PreimageType},
    merkle::MerkleTree,
    operator::OperatorClaimSigs,
    traits::operator_db::OperatorDBConnector,
};

#[derive(Debug, Clone)]
pub struct OperatorMockDB {
    deposit_take_sigs: Vec<OperatorClaimSigs>,
    connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    connector_tree_hashes: Vec<Vec<Vec<HashType>>>,
    inscription_txs: Vec<InscriptionTxs>,
    withdrawals_merkle_tree: MerkleTree<DEPTH>,
    withdrawals_payment_txids: Vec<Txid>,
    connector_tree_utxos: Vec<ConnectorTreeUTXOs>,
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
}
impl OperatorDBConnector for OperatorMockDB {
    fn get_deposit_index(&self) -> usize {
        self.deposit_take_sigs.len()
    }

    // fn get_deposit_take_sigs(&self) -> Vec<OperatorClaimSigs> {
    //     self.deposit_take_sigs.clone()
    // }

    fn add_deposit_take_sigs(&mut self, deposit_take_sigs: OperatorClaimSigs) {
        self.deposit_take_sigs.push(deposit_take_sigs);
    }

    fn get_connector_tree_preimages_level(&self, period: usize, level: usize) -> Vec<PreimageType> {
        self.connector_tree_preimages[period][level].clone()
    }

    fn get_connector_tree_preimages(
        &self,
        period: usize,
        level: usize,
        idx: usize,
    ) -> PreimageType {
        self.connector_tree_preimages[period][level][idx].clone()
    }

    fn set_connector_tree_preimages(
        &mut self,
        connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    ) {
        self.connector_tree_preimages = connector_tree_preimages;
    }

    fn get_connector_tree_hash(&self, period: usize, level: usize, idx: usize) -> HashType {
        self.connector_tree_hashes[period][level][idx]
    }

    fn set_connector_tree_hashes(&mut self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>) {
        self.connector_tree_hashes = connector_tree_hashes;
    }

    fn get_inscription_txs_len(&self) -> usize {
        self.inscription_txs.len()
    }

    fn add_to_inscription_txs(&mut self, inscription_txs: InscriptionTxs) {
        self.inscription_txs.push(inscription_txs);
    }

    fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        self.withdrawals_merkle_tree.index
    }

    fn add_to_withdrawals_merkle_tree(&mut self, hash: HashType) {
        self.withdrawals_merkle_tree.add(hash);
    }

    fn add_to_withdrawals_payment_txids(&mut self, txid: Txid) {
        self.withdrawals_payment_txids.push(txid);
    }

    fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorTreeUTXOs {
        self.connector_tree_utxos[idx].clone()
    }

    fn get_connector_tree_utxos(&self) -> Vec<ConnectorTreeUTXOs> {
        self.connector_tree_utxos.clone()
    }

    fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorTreeUTXOs>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }
}
