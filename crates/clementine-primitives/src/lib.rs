//! # Clementine Primitives
//!
//! Primitive types shared across clementine crates.
//!
//! This crate contains foundational types with no internal dependencies,
//! enabling them to be used by both `clementine-errors` and `clementine-core`.

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};

// ============================================================================
// Macro for TryFrom<Vec<u8>> implementations
// ============================================================================

macro_rules! impl_try_from_vec_u8 {
    ($name:ident, $size:expr) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = &'static str;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                if value.len() == $size {
                    Ok($name(value.try_into().unwrap()))
                } else {
                    Err(concat!("Expected a Vec<u8> of length ", stringify!($size)))
                }
            }
        }
    };
}

// ============================================================================
// Byte Arrays
// ============================================================================

/// 32-byte array with hex serialization and sqlx support.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray32(#[serde(with = "hex::serde")] pub [u8; 32]);

impl_try_from_vec_u8!(ByteArray32, 32);

/// 64-byte array with hex serialization and sqlx support.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray64(#[serde(with = "hex::serde")] pub [u8; 64]);

impl_try_from_vec_u8!(ByteArray64, 64);

/// 66-byte array with hex serialization and sqlx support.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray66(#[serde(with = "hex::serde")] pub [u8; 66]);

impl_try_from_vec_u8!(ByteArray66, 66);

// ============================================================================
// Address Types
// ============================================================================

/// Type alias for 20-byte EVM address.
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

impl_try_from_vec_u8!(EVMAddress, 20);

// ============================================================================
// UTXO Types
// ============================================================================

/// A Bitcoin UTXO (Unspent Transaction Output).
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: bitcoin::TxOut,
}

/// Tree structure for connector UTXOs.
pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;

/// Inscription transaction data: (outpoint, txid).
pub type InscriptionTxs = (OutPoint, Txid);

// ============================================================================
// Round Types
// ============================================================================

/// Type alias for challenge preimage hash (20 bytes).
pub type PublicHash = [u8; 20];

/// Type alias for secret preimage (20 bytes).
pub type SecretPreimage = [u8; 20];

/// Round index for bridge operators.
///
/// `Collateral` represents the collateral UTXO.
/// `Round(index)` represents the rounds of the bridge operators (0-indexed).
/// As a single u32, collateral is represented as 0 and rounds are represented starting from 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Ord, PartialOrd,
)]
pub enum RoundIndex {
    Collateral,
    Round(usize), // 0-indexed
}

impl RoundIndex {
    /// Converts the round to a 0-indexed index.
    pub fn to_index(&self) -> usize {
        match self {
            RoundIndex::Collateral => 0,
            RoundIndex::Round(index) => *index + 1,
        }
    }

    /// Converts a 0-indexed index to a RoundIndex.
    /// Use this only when dealing with 0-indexed data. Currently these are data coming from the database and rpc.
    pub fn from_index(index: usize) -> Self {
        if index == 0 {
            RoundIndex::Collateral
        } else {
            RoundIndex::Round(index - 1)
        }
    }

    /// Returns the next RoundIndex.
    pub fn next_round(&self) -> Self {
        match self {
            RoundIndex::Collateral => RoundIndex::Round(0),
            RoundIndex::Round(index) => RoundIndex::Round(*index + 1),
        }
    }

    /// Creates an iterator over rounds from 0 to num_rounds (exclusive).
    /// Only iterates actual rounds, collateral is not included.
    pub fn iter_rounds(num_rounds: usize) -> impl Iterator<Item = RoundIndex> {
        Self::iter_rounds_range(0, num_rounds)
    }

    /// Creates an iterator over rounds from start to end (exclusive).
    /// Only iterates actual rounds, collateral is not included.
    pub fn iter_rounds_range(start: usize, end: usize) -> impl Iterator<Item = RoundIndex> {
        (start..end).map(RoundIndex::Round)
    }
}

// ============================================================================
// Transaction Types
// ============================================================================

/// Types of all transactions that can be created.
///
/// Some transactions have a `(usize)` index as there are multiple instances
/// of the same transaction type per kickoff.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TransactionType {
    // --- Transaction Types ---
    AssertTimeout(usize),
    BurnUnusedKickoffConnectors,
    Challenge,
    ChallengeTimeout,
    Disprove,
    DisproveTimeout,
    EmergencyStop,
    Kickoff,
    KickoffNotFinalized,
    LatestBlockhash,
    LatestBlockhashTimeout,
    MiniAssert(usize),
    MoveToVault,
    OperatorChallengeAck(usize),
    OperatorChallengeNack(usize),
    OptimisticPayout,
    Payout,
    ReadyToReimburse,
    Reimburse,
    ReplacementDeposit,
    Round,
    UnspentKickoff(usize),
    WatchtowerChallenge(usize),
    WatchtowerChallengeTimeout(usize),

    // --- Transaction Subsets ---
    /// Includes all tx's that need to be signed for a deposit for verifiers.
    AllNeededForDeposit,
    /// Yields kickoff txid from the sighash stream.
    YieldKickoffTxid,

    /// For testing and for values to be replaced later.
    Dummy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_index_to_from_index() {
        assert_eq!(RoundIndex::Collateral.to_index(), 0);
        assert_eq!(RoundIndex::Round(0).to_index(), 1);
        assert_eq!(RoundIndex::Round(5).to_index(), 6);

        assert_eq!(RoundIndex::from_index(0), RoundIndex::Collateral);
        assert_eq!(RoundIndex::from_index(1), RoundIndex::Round(0));
        assert_eq!(RoundIndex::from_index(6), RoundIndex::Round(5));
    }

    #[test]
    fn test_round_index_next_round() {
        assert_eq!(RoundIndex::Collateral.next_round(), RoundIndex::Round(0));
        assert_eq!(RoundIndex::Round(0).next_round(), RoundIndex::Round(1));
    }

    #[test]
    fn test_round_index_iter() {
        let rounds: Vec<_> = RoundIndex::iter_rounds(3).collect();
        assert_eq!(
            rounds,
            vec![
                RoundIndex::Round(0),
                RoundIndex::Round(1),
                RoundIndex::Round(2)
            ]
        );
    }

    #[test]
    fn test_byte_array_try_from() {
        let vec32: Vec<u8> = vec![0; 32];
        assert!(ByteArray32::try_from(vec32).is_ok());
        assert!(ByteArray32::try_from(vec![0; 31]).is_err());
    }
}
