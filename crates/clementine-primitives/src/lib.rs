//! # Clementine Primitives
//!
//! Primitive types shared across clementine crates.
//!
//! This crate contains foundational types with no internal dependencies,
//! enabling them to be used by both `clementine-errors` and `clementine-core`.

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

lazy_static::lazy_static! {
    /// Global secp context.
    pub static ref SECP: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();

    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    ///
    /// It is used to create a taproot address where the internal key is not spendable.
    /// Here are the other protocols that use this key:
    /// - Babylon:https://github.com/babylonlabs-io/btc-staking-ts/blob/v0.4.0-rc.2/src/constants/internalPubkey.ts
    /// - Ark: https://github.com/ark-network/ark/blob/cba48925bcc836cc55f9bb482f2cd1b76d78953e/common/tree/validation.go#L47
    /// - BitVM: https://github.com/BitVM/BitVM/blob/2dd2e0e799d2b9236dd894da3fee8c4c4893dcf1/bridge/src/scripts.rs#L16
    /// - Best in Slot: https://github.com/bestinslot-xyz/brc20-programmable-module/blob/2113bdd73430a8c3757e537cb63124a6cb33dfab/src/evm/precompiles/get_locked_pkscript_precompile.rs#L53
    /// - https://github.com/BlockstreamResearch/options/blob/36a77175919101393b49f1211732db762cc7dfc1/src/options_lib/src/contract.rs#L132
    pub static ref UNSPENDABLE_XONLY_PUBKEY: bitcoin::secp256k1::XOnlyPublicKey =
        bitcoin::secp256k1::XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").expect("this key is valid");
}

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

use bitcoin::transaction::Version;
use bitcoin::Amount;

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330);

/// Non-standard V3 transaction version.
pub const NON_STANDARD_V3: Version = Version(3);

/// Number of assert transactions in the protocol.
pub const NUMBER_OF_ASSERT_TXS: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Enumerates protocol-specific UTXO output indices for transaction construction.
/// Used to identify the vout of specific UTXOs in protocol transactions.
pub enum UtxoVout {
    /// The vout of the assert utxo in KickoffTx
    Assert(usize),
    /// The vout of the watchtower challenge utxo in KickoffTx
    WatchtowerChallenge(usize),
    /// The vout of the watchtower challenge ack utxo in KickoffTx
    WatchtowerChallengeAck(usize),
    /// The vout of the challenge utxo in KickoffTx
    Challenge,
    /// The vout of the kickoff finalizer utxo in KickoffTx
    KickoffFinalizer,
    /// The vout of the reimburse utxo in KickoffTx
    ReimburseInKickoff,
    /// The vout of the disprove utxo in KickoffTx
    Disprove,
    /// The vout of the latest blockhash utxo in KickoffTx
    LatestBlockhash,
    /// The vout of the deposited btc utxo in MoveTx
    DepositInMove,
    /// The vout of the reimburse connector utxo in RoundTx
    ReimburseInRound(usize, usize),
    /// The vout of the kickoff utxo in RoundTx
    Kickoff(usize),
    /// The vout of the collateral utxo in RoundTx
    CollateralInRound,
    /// The vout of the collateral utxo in ReadyToReimburseTx
    CollateralInReadyToReimburse,
}

impl UtxoVout {
    /// Returns the vout index for this UTXO in the corresponding transaction.
    pub fn get_vout(self) -> u32 {
        match self {
            UtxoVout::Assert(idx) => idx as u32 + 5,
            UtxoVout::WatchtowerChallenge(idx) => (2 * idx + 5 + NUMBER_OF_ASSERT_TXS) as u32,
            UtxoVout::WatchtowerChallengeAck(idx) => (2 * idx + 6 + NUMBER_OF_ASSERT_TXS) as u32,
            UtxoVout::Challenge => 0,
            UtxoVout::KickoffFinalizer => 1,
            UtxoVout::ReimburseInKickoff => 2,
            UtxoVout::Disprove => 3,
            UtxoVout::LatestBlockhash => 4,
            UtxoVout::ReimburseInRound(idx, num_kickoffs_per_round) => {
                (num_kickoffs_per_round + idx + 1) as u32
            }
            UtxoVout::Kickoff(idx) => idx as u32 + 1,
            UtxoVout::DepositInMove => 0,
            UtxoVout::CollateralInRound => 0,
            UtxoVout::CollateralInReadyToReimburse => 0,
        }
    }
}

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

impl std::fmt::Display for RoundIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundIndex::Collateral => write!(f, "Collateral"),
            RoundIndex::Round(index) => write!(f, "Round({index})"),
        }
    }
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

/// Events emitted by the Bitcoin syncer.
/// It emits the block_id of the block in the db that was saved.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BitcoinSyncerEvent {
    NewBlock(u32),
    ReorgedBlock(u32),
}

use eyre::Context;

impl TryFrom<(String, i32)> for BitcoinSyncerEvent {
    type Error = eyre::Report;
    fn try_from(value: (String, i32)) -> Result<Self, Self::Error> {
        match value.0.as_str() {
            "new_block" => Ok(BitcoinSyncerEvent::NewBlock(
                u32::try_from(value.1).wrap_err("Int conversion error for new_block")?,
            )),
            "reorged_block" => Ok(BitcoinSyncerEvent::ReorgedBlock(
                u32::try_from(value.1).wrap_err("Int conversion error for reorged_block")?,
            )),
            _ => Err(eyre::eyre!("Invalid event type: {}", value.0)),
        }
    }
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
