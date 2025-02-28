use super::context::StateContext;

use bitcoin::{OutPoint, Txid};
use statig::awaitable;
use statig::awaitable::InitializedStateMachine;
use statig::IntoStateMachine;

use std::future::Future;

use super::Owner;

use super::block_cache::BlockCache;

pub(crate) trait BlockMatcher {
    type StateEvent;

    fn match_block(&self, block: &super::block_cache::BlockCache) -> Vec<Self::StateEvent>;
}

// Matcher for state machines to define what they're interested in
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Matcher {
    SentTx(Txid),
    SpentUtxo(OutPoint),
    BlockHeight(u32),
}

impl Matcher {
    pub fn matches(&self, block: &BlockCache) -> bool {
        match self {
            Matcher::SentTx(txid) => block.contains_txid(txid),
            Matcher::SpentUtxo(outpoint) => block.is_utxo_spent(outpoint),
            Matcher::BlockHeight(height) => *height == block.block_height,
        }
    }
}
