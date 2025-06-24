use bitcoin::{OutPoint, Txid};
use std::cmp::Ordering;

use super::block_cache::BlockCache;

pub(crate) trait BlockMatcher {
    type StateEvent;

    fn match_block(&self, block: &super::block_cache::BlockCache) -> Vec<Self::StateEvent>;
}

// Matcher for state machines to define what they're interested in
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum Matcher {
    SentTx(Txid),
    SpentUtxo(OutPoint),
    /// This matcher is used to determine an outpoint was spent, but the tx that spent is does not have any of the txids.
    /// It is used either to detect timeouts (like AssertTimeout) or exit from the protocol (like when Operator sends its collateral back to its wallet).
    SpentUtxoButNotTxid(OutPoint, Vec<Txid>),
    BlockHeight(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatcherOrd {
    TxIndex(usize),
    BlockHeight,
}

impl PartialOrd for MatcherOrd {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MatcherOrd {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (MatcherOrd::TxIndex(a), MatcherOrd::TxIndex(b)) => a.cmp(b),
            (MatcherOrd::BlockHeight, MatcherOrd::BlockHeight) => Ordering::Equal,
            (MatcherOrd::BlockHeight, _) => Ordering::Less,
            (_, MatcherOrd::BlockHeight) => Ordering::Greater,
        }
    }
}

impl Matcher {
    pub fn matches(&self, block: &BlockCache) -> Option<MatcherOrd> {
        match self {
            Matcher::SentTx(txid) if block.contains_txid(txid) => Some(MatcherOrd::TxIndex(
                *block.txids.get(txid).expect("txid is in cache"),
            )),
            Matcher::SpentUtxo(outpoint) if (block.is_utxo_spent(outpoint)) => Some(
                MatcherOrd::TxIndex(*block.spent_utxos.get(outpoint).expect("utxo is in cache")),
            ),
            Matcher::BlockHeight(height) if *height <= block.block_height => {
                Some(MatcherOrd::BlockHeight)
            }
            Matcher::SpentUtxoButNotTxid(outpoint, txids)
                if block.is_utxo_spent(outpoint)
                    && !txids.iter().any(|txid| block.contains_txid(txid)) =>
            {
                Some(MatcherOrd::TxIndex(
                    *block.spent_utxos.get(outpoint).expect("utxo is in cache"),
                ))
            }
            _ => None,
        }
    }
}
