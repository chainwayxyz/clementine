use bitcoin::{Block, OutPoint, Transaction, Txid, Witness};
use std::collections::HashMap;

/// Block cache to optimize Txid and UTXO lookups for a block
#[derive(Debug, Clone, Default)]
pub struct BlockCache {
    pub(crate) txids: HashMap<Txid, usize>,
    pub(crate) spent_utxos: HashMap<OutPoint, usize>,
    pub(crate) block_height: u32,
    pub(crate) block: Option<Block>,
}

impl BlockCache {
    pub fn new() -> Self {
        Self {
            txids: HashMap::new(),
            spent_utxos: HashMap::new(),
            block_height: 0,
            block: None,
        }
    }

    pub fn update_with_block(&mut self, block: &Block, block_height: u32) {
        self.block_height = block_height;
        for (idx, tx) in block.txdata.iter().enumerate() {
            self.txids.insert(tx.compute_txid(), idx);

            // Mark UTXOs as spent
            for input in &tx.input {
                self.spent_utxos.insert(input.previous_output, idx);
            }
        }
        self.block = Some(block.clone());
    }

    pub fn get_tx_with_index(&self, idx: usize) -> Option<&Transaction> {
        self.block.as_ref().map(|block| &block.txdata[idx])
    }

    pub fn get_tx_of_utxo(&self, utxo: &OutPoint) -> Option<&Transaction> {
        self.spent_utxos
            .get(utxo)
            .and_then(|idx| self.get_tx_with_index(*idx))
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
