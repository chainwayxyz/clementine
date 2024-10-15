//! # Wrapper For Converting Proto Structures

use super::clementine::Outpoint;
use bitcoin::{hashes::Hash, OutPoint, Txid};

impl From<Outpoint> for OutPoint {
    fn from(value: Outpoint) -> Self {
        OutPoint {
            txid: Txid::all_zeros(),
            vout: value.vout,
        }
    }
}
