use bitcoin::{OutPoint, Txid};
use std::cmp::Ordering;

use super::block_cache::BlockCache;

/// A trait that will return a single event when a block matches any of the matchers.
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
    /// This matcher is used to determine that an outpoint was spent, but the txid of the tx that spent the outpoint
    /// is not equal to any of the txids in the vector.
    /// For many transactions in clementine, there are many utxos that can be spent in two ways:
    /// 1. A nofn-presigned timeout transaction. These timeout transactions have fixed txid (because they are nofn signed) and can be sent after the utxo is not spent by operator before the timelock.
    /// 2. A transaction that spends the utxo to reveal/inscribe something in Bitcoin. These transactions are not nofn presigned and can be spent by operators/verifiers in any way they want as long as the witness is valid so there are no fixed txids for these transactions. (Transactions like Watchtower Challenge, Operator Assert, etc.)
    ///
    /// This matcher is used to detect the second case, and the Txid vector is used to check if utxo is instead spent by a timeout transaction.
    /// This matcher is used for detection of transactions like Watchtower Challenge, Operator Assert, etc.
    SpentUtxoButNotTxid(OutPoint, Vec<Txid>),
    BlockHeight(u32),
}

/// An enum that represents the order of the matchers.
/// The reason for the order is to make sure if a transaction has lower index in the block,
/// any events resulting from that transaction are processed first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatcherOrd {
    /// Matcher ordering for matchers concerning a single tx
    TxIndex(usize),
    /// Matcher ordering for matchers concerning a block height
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
    /// Returns the order of the matcher if the block matches the matcher.
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
