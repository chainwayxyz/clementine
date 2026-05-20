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
use bitcoin::{Amount, Sequence, Weight};

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330);

/// Non-standard V3 transaction version.
pub const NON_STANDARD_V3: Version = Version(3);

/// Default sequence for RBF-enabled transactions without locktime semantics.
pub const DEFAULT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// Number of assert transactions in the protocol.
pub const NUMBER_OF_ASSERT_TXS: usize = 36;

/// Fee rate expressed in satoshis per kilovbyte (sat/kvB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FeeRateKvb(u64);

impl FeeRateKvb {
    /// Creates a fee rate from sat/kvB.
    pub fn from_sat_per_kvb(sat_per_kvb: u64) -> Self {
        Self(sat_per_kvb)
    }

    /// Creates a fee rate from sat/vB, returning `None` on overflow.
    pub fn from_sat_per_vb(sat_per_vb: u64) -> Option<Self> {
        sat_per_vb.checked_mul(1000).map(Self)
    }

    /// Creates a fee rate from sat/vB without overflow checks.
    pub fn from_sat_per_vb_unchecked(sat_per_vb: u64) -> Self {
        Self(sat_per_vb * 1000)
    }

    /// Creates a fee rate from sat/kwu.
    ///
    /// Note: 1 kvB = 4 kwu.
    pub fn from_sat_per_kwu(sat_per_kwu: u64) -> Self {
        Self(sat_per_kwu.saturating_mul(4))
    }

    /// Returns the fee rate in sat/kvB.
    pub fn to_sat_per_kvb(self) -> u64 {
        self.0
    }

    /// Returns the fee rate in sat/vB, rounded up.
    pub fn to_sat_per_vb_ceil(self) -> u64 {
        self.0.div_ceil(1000)
    }

    /// Returns the fee rate in sat/kwu, rounded up.
    pub fn to_sat_per_kwu_ceil(self) -> u64 {
        self.0.div_ceil(4)
    }

    /// Computes the fee for a given number of vbytes.
    pub fn fee_vb(self, vbytes: u64) -> Option<Amount> {
        let fee_sat = self.0.checked_mul(vbytes)?;
        Some(Amount::from_sat(fee_sat.div_ceil(1000)))
    }

    /// Multiplies the fee rate by a scalar, returning `None` on overflow.
    pub fn checked_mul(self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    /// Computes the fee for a given weight (WU).
    pub fn fee_wu(self, weight: Weight) -> Option<Amount> {
        self.fee_vb(weight.to_vbytes_ceil())
    }
}

impl std::fmt::Display for FeeRateKvb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} sat/kvB", self.0)
    }
}

// impl From<FeeRate> for FeeRateKvb {
//     fn from(value: FeeRate) -> Self {
//         Self::from_sat_per_kwu(value.to_sat_per_kwu())
//     }
// }

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
/// `Round(index)` represents the rounds of the bridge operators (zero-based).
/// As a single u32, collateral is represented as 0 and rounds are represented starting from 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Ord, PartialOrd,
)]
pub enum BridgeRound {
    Collateral,
    Round(usize), // zero-based
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundIdxConversionError {
    InvalidRoundIndex(BridgeRound),
}

impl std::fmt::Display for RoundIdxConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundIdxConversionError::InvalidRoundIndex(round) => write!(
                f,
                "Invalid round index `{round}`: collateral cannot be used where a protocol round is required"
            ),
        }
    }
}

impl std::error::Error for RoundIdxConversionError {}

impl std::fmt::Display for BridgeRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeRound::Collateral => write!(f, "Collateral"),
            BridgeRound::Round(index) => write!(f, "Round({index})"),
        }
    }
}

impl BridgeRound {
    /// Converts the round to a zero-based index.
    pub fn to_index(&self) -> usize {
        match self {
            BridgeRound::Collateral => 0,
            BridgeRound::Round(index) => *index + 1,
        }
    }

    /// Converts a zero-based index to a BridgeRound.
    /// Use this only when dealing with zero-based data. Currently these are data coming from the database and rpc.
    pub fn from_index(index: usize) -> Self {
        if index == 0 {
            BridgeRound::Collateral
        } else {
            BridgeRound::Round(index - 1)
        }
    }

    /// Returns the next BridgeRound.
    pub fn next_round(&self) -> Self {
        match self {
            BridgeRound::Collateral => BridgeRound::Round(0),
            BridgeRound::Round(index) => BridgeRound::Round(*index + 1),
        }
    }

    /// Creates an iterator over rounds from 0 to num_rounds (exclusive).
    /// Only iterates actual rounds, collateral is not included.
    pub fn iter_rounds(num_rounds: usize) -> impl Iterator<Item = BridgeRound> {
        Self::iter_rounds_range(0, num_rounds)
    }

    /// Creates an iterator over rounds from start to end (exclusive).
    /// Only iterates actual rounds, collateral is not included.
    pub fn iter_rounds_range(start: usize, end: usize) -> impl Iterator<Item = BridgeRound> {
        (start..end).map(BridgeRound::Round)
    }

    /// Converts a [`BridgeRound`] to typed [`RoundIdx`].
    ///
    /// Returns an error for [`BridgeRound::Collateral`] because collateral is not a valid
    /// protocol round.
    pub fn to_round_idx(self) -> Result<RoundIdx, RoundIdxConversionError> {
        match self {
            BridgeRound::Round(idx) => Ok(RoundIdx::new(idx)),
            BridgeRound::Collateral => Err(RoundIdxConversionError::InvalidRoundIndex(
                BridgeRound::Collateral,
            )),
        }
    }
}

// ============================================================================
// Transaction Types
// ============================================================================

/// Typed round index used by transaction IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct RoundIdx(pub usize);

impl RoundIdx {
    pub fn new(value: usize) -> Self {
        Self(value)
    }
}

/// Typed kickoff index used by transaction IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct KickoffIdx(pub usize);

impl KickoffIdx {
    pub fn new(value: usize) -> Self {
        Self(value)
    }
}

/// Canonical transaction ID for the static protocol runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TransactionType {
    MoveToVault,
    EmergencyStop,
    Round(RoundIdx),
    ReadyToReimburse(RoundIdx),
    Kickoff(RoundIdx, KickoffIdx),
    Challenge(RoundIdx, KickoffIdx),
    ChallengeTimeout(RoundIdx, KickoffIdx),
    KickoffNotFinalized(RoundIdx, KickoffIdx),
    WatchtowerChallenge(RoundIdx, KickoffIdx, usize),
    WatchtowerChallengeTimeout(RoundIdx, KickoffIdx, usize),
    OperatorChallengeNack(RoundIdx, KickoffIdx, usize),
    OperatorChallengeAck(RoundIdx, KickoffIdx, usize),
    LatestBlockhash(RoundIdx, KickoffIdx),
    LatestBlockhashTimeout(RoundIdx, KickoffIdx),
    MiniAssert(RoundIdx, KickoffIdx, usize),
    AssertTimeout(RoundIdx, KickoffIdx, usize),
    Disprove(RoundIdx, KickoffIdx),
    DisproveTimeout(RoundIdx, KickoffIdx),
    UnspentKickoff(RoundIdx, KickoffIdx),
    BurnUnusedKickoffConnectors(RoundIdx, Vec<usize>),
    Reimburse(RoundIdx, KickoffIdx),
    Payout,
    OptimisticPayout,
    ReplacementDeposit,
    YieldKickoffTxid,
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
        assert_eq!(BridgeRound::Collateral.to_index(), 0);
        assert_eq!(BridgeRound::Round(0).to_index(), 1);
        assert_eq!(BridgeRound::Round(5).to_index(), 6);

        assert_eq!(BridgeRound::from_index(0), BridgeRound::Collateral);
        assert_eq!(BridgeRound::from_index(1), BridgeRound::Round(0));
        assert_eq!(BridgeRound::from_index(6), BridgeRound::Round(5));
    }

    #[test]
    fn test_round_index_next_round() {
        assert_eq!(BridgeRound::Collateral.next_round(), BridgeRound::Round(0));
        assert_eq!(BridgeRound::Round(0).next_round(), BridgeRound::Round(1));
    }

    #[test]
    fn test_round_index_iter() {
        let rounds: Vec<_> = BridgeRound::iter_rounds(3).collect();
        assert_eq!(
            rounds,
            vec![
                BridgeRound::Round(0),
                BridgeRound::Round(1),
                BridgeRound::Round(2)
            ]
        );
    }

    #[test]
    fn test_round_index_to_round_idx() {
        assert_eq!(
            BridgeRound::Round(3).to_round_idx().unwrap(),
            RoundIdx::new(3)
        );
        assert!(BridgeRound::Collateral.to_round_idx().is_err());
    }

    #[test]
    fn test_byte_array_try_from() {
        let vec32: Vec<u8> = vec![0; 32];
        assert!(ByteArray32::try_from(vec32).is_ok());
        assert!(ByteArray32::try_from(vec![0; 31]).is_err());
    }
}
