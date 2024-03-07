use crate::{operator::OperatorClaimSigs, ConnectorUTXOTree, InscriptionTxs};
use bitcoin::Txid;
use circuit_helpers::{HashType, PreimageType};
pub trait OperatorDBConnector: std::fmt::Debug {
    fn get_deposit_index(&self) -> usize;
    fn add_deposit_take_sigs(&mut self, deposit_take_sigs: OperatorClaimSigs);
    fn get_connector_tree_preimages_level(&self, period: usize, level: usize) -> Vec<PreimageType>;
    fn get_connector_tree_preimages(&self, period: usize, level: usize, idx: usize)
        -> PreimageType;
    fn set_connector_tree_preimages(
        &mut self,
        connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    );
    fn get_connector_tree_hash(&self, period: usize, level: usize, idx: usize) -> HashType;
    fn set_connector_tree_hashes(&mut self, connector_tree_hashes: Vec<Vec<Vec<HashType>>>);
    fn get_inscription_txs_len(&self) -> usize;
    fn add_to_inscription_txs(&mut self, inscription_txs: InscriptionTxs);
    fn get_withdrawals_merkle_tree_index(&self) -> u32;
    fn add_to_withdrawals_merkle_tree(&mut self, hash: HashType);
    fn add_to_withdrawals_payment_txids(&mut self, period: usize, txid: Txid);
    fn get_connector_tree_utxo(&self, idx: usize) -> ConnectorUTXOTree;
    fn get_connector_tree_utxos(&self) -> Vec<ConnectorUTXOTree>;
    fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorUTXOTree>);
    fn get_start_block_height(&self) -> u64;
    fn set_start_block_height(&mut self, start_block_height: u64);

    fn set_period_relative_block_heights(&mut self, period_relative_block_heights: Vec<u32>);
    fn get_period_relative_block_heights(&self) -> Vec<u32>;
}
