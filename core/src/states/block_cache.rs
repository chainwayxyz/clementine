use bitcoin::Block;

use bitcoin::OutPoint;

use std::collections::HashSet;

use bitcoin::Transaction;

use bitcoin::Txid;

use std::collections::HashMap;

/// Block cache to optimize Txid and UTXO lookups for a block
#[derive(Debug, Clone, Default)]
pub struct BlockCache {
    pub(crate) txids: HashMap<Txid, Transaction>,
    pub(crate) spent_utxos: HashSet<OutPoint>,
    pub(crate) block_height: u32,
}

impl BlockCache {
    pub fn new() -> Self {
        Self {
            txids: HashMap::new(),
            spent_utxos: HashSet::new(),
            block_height: 0,
        }
    }

    pub fn update_with_block(&mut self, block: &Block, block_height: u32) {
        self.block_height = block_height;
        for tx in &block.txdata {
            self.txids.insert(tx.compute_txid(), tx.clone());

            // Mark UTXOs as spent
            for input in &tx.input {
                self.spent_utxos.insert(input.previous_output);
            }
        }
    }

    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.txids.contains_key(txid)
    }

    pub fn is_utxo_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_utxos.contains(outpoint)
    }
}
