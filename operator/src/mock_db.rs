use bitcoin::Txid;
use circuit_helpers::{constants::WITHDRAWAL_MERKLE_TREE_DEPTH, HashType, PreimageType};

use crate::{
    merkle::MerkleTree, operator::OperatorClaimSigs, traits::operator_db::OperatorDBConnector,
    ConnectorUTXOTree, HashTree, InscriptionTxs, PreimageTree, WithdrawalPayment,
};

#[derive(Debug, Clone)]
pub struct OperatorMockDB {
    deposit_take_sigs: Vec<OperatorClaimSigs>,
    connector_tree_preimages: Vec<PreimageTree>,
    inscribed_connector_tree_preimages: Vec<Vec<PreimageType>>,
    connector_tree_hashes: Vec<HashTree>,
    inscription_txs: Vec<InscriptionTxs>,
    withdrawals_merkle_tree: MerkleTree<WITHDRAWAL_MERKLE_TREE_DEPTH>,
    withdrawals_payment_txids: Vec<Vec<WithdrawalPayment>>,
    connector_tree_utxos: Vec<ConnectorUTXOTree>,
    start_block_height: u64,
    period_relative_block_heights: Vec<u32>,
}

impl OperatorMockDB {
    pub fn new() -> Self {
        Self {
            deposit_take_sigs: Vec::new(),
            // deposit_merkle_tree: MerkleTree::new(),
            inscribed_connector_tree_preimages: Vec::new(),
            withdrawals_merkle_tree: MerkleTree::new(),
            withdrawals_payment_txids: Vec::new(),
            inscription_txs: Vec::new(),
            connector_tree_preimages: Vec::new(),
            connector_tree_hashes: Vec::new(),
            // deposit_utxos: Vec::new(),
            // move_utxos: Vec::new(),
            connector_tree_utxos: Vec::new(),
            start_block_height: 0,
            period_relative_block_heights: Vec::new(),
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

    fn get_inscription_txs(&self) -> Vec<InscriptionTxs> {
        self.inscription_txs.clone()
    }

    fn get_withdrawals_merkle_tree_index(&self) -> u32 {
        self.withdrawals_merkle_tree.index
    }

    fn add_to_withdrawals_merkle_tree(&mut self, hash: HashType) {
        self.withdrawals_merkle_tree.add(hash);
    }

    fn add_to_withdrawals_payment_txids(
        &mut self,
        period: usize,
        withdrawal_payment: WithdrawalPayment,
    ) {
        while period >= self.withdrawals_payment_txids.len() {
            self.withdrawals_payment_txids.push(Vec::new());
        }
        self.withdrawals_payment_txids[period].push(withdrawal_payment);
    }

    fn get_withdrawals_payment_for_period(&self, period: usize) -> Vec<WithdrawalPayment> {
        self.withdrawals_payment_txids[period].clone()
    }

    fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorUTXOTree {
        self.connector_tree_utxos[idx].clone()
    }

    fn get_connector_tree_utxos(&self) -> Vec<ConnectorUTXOTree> {
        self.connector_tree_utxos.clone()
    }

    fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorUTXOTree>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }

    fn get_start_block_height(&self) -> u64 {
        self.start_block_height
    }

    fn set_start_block_height(&mut self, start_block_height: u64) {
        self.start_block_height = start_block_height;
    }

    fn set_period_relative_block_heights(&mut self, period_relative_block_heights: Vec<u32>) {
        self.period_relative_block_heights = period_relative_block_heights;
    }
    fn get_period_relative_block_heights(&self) -> Vec<u32> {
        self.period_relative_block_heights.clone()
    }

    fn add_inscribed_preimages(&mut self, period: usize, preimages: Vec<PreimageType>) {
        while period >= self.inscribed_connector_tree_preimages.len() {
            self.inscribed_connector_tree_preimages.push(Vec::new());
        }
        self.inscribed_connector_tree_preimages[period] = preimages;
    }
    fn get_inscribed_preimages(&self, period: usize) -> Vec<PreimageType> {
        self.inscribed_connector_tree_preimages[period].clone()
    }
}
