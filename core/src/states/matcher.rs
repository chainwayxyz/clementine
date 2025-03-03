use super::block_cache::BlockCache;
use bitcoin::{OutPoint, Txid};

pub(crate) trait BlockMatcher {
    type StateEvent;

    fn match_block(&self, block: &super::block_cache::BlockCache) -> Vec<Self::StateEvent>;
}

// Matcher for state machines to define what they're interested in
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Matcher {
    SentTx(Txid),
    SpentUtxo(OutPoint),
    // stuff like watchtower challenge utxos, operator asserts utxos, that can be sent as a timeout (thus nofn)
    // or by the entity themselves (meaning it is an winternitz assert)
    SpentUtxoButNotTimeout(OutPoint, Txid),
    BlockHeight(u32),
}

impl Matcher {
    // TODO: sort by matched tx index
    pub fn matches(&self, block: &BlockCache) -> bool {
        match self {
            Matcher::SentTx(txid) => block.contains_txid(txid),
            Matcher::SpentUtxo(outpoint) => block.is_utxo_spent(outpoint),
            Matcher::BlockHeight(height) => *height <= block.block_height,
            Matcher::SpentUtxoButNotTimeout(outpoint, txid) => {
                block.is_utxo_spent(outpoint) && !block.contains_txid(txid)
            }
        }
    }
}
