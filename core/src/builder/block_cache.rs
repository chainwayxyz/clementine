use bitcoin::{Block, OutPoint, Transaction, Txid, Witness};
use std::collections::HashMap;

/// Block cache to optimize Txid and UTXO lookups for a block
#[derive(Debug, Clone)]
pub struct BlockCache {
    pub(crate) txids: HashMap<Txid, usize>,
    pub(crate) spent_utxos: HashMap<OutPoint, usize>,
    pub(crate) block_height: u32,
    pub(crate) block: Block,
}

impl BlockCache {
    pub fn from_block(block: Block, block_height: u32) -> Self {
        let mut txids = HashMap::new();
        let mut spent_utxos = HashMap::new();
        for (idx, tx) in block.txdata.iter().enumerate() {
            txids.insert(tx.compute_txid(), idx);

            // Mark UTXOs as spent
            for input in &tx.input {
                spent_utxos.insert(input.previous_output, idx);
            }
        }

        Self {
            txids,
            spent_utxos,
            block_height,
            block,
        }
    }

    pub fn get_tx_with_index(&self, idx: usize) -> Option<&Transaction> {
        self.block.txdata.get(idx)
    }

    pub fn get_tx_of_utxo(&self, utxo: &OutPoint) -> Option<&Transaction> {
        self.spent_utxos
            .get(utxo)
            .and_then(|idx| self.get_tx_with_index(*idx))
    }

    pub fn get_txid_of_utxo(&self, utxo: &OutPoint) -> Option<Txid> {
        self.get_tx_of_utxo(utxo).map(|tx| tx.compute_txid())
    }

    pub fn get_witness_of_utxo(&self, utxo: &OutPoint) -> Option<Witness> {
        self.get_tx_of_utxo(utxo).and_then(|tx| {
            tx.input
                .iter()
                .find(|input| input.previous_output == *utxo)
                .map(|input| input.witness.clone())
        })
    }

    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.txids.contains_key(txid)
    }

    pub fn is_utxo_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_utxos.contains_key(outpoint)
    }
}
