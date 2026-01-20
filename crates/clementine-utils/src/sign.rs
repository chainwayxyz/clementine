//! Signing information for taproot spends.

use bitcoin::{TapNodeHash, TapSighashType};
use serde::{Deserialize, Serialize};

/// Spend path information for RBF signing.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum RbfSigningSpendPath {
    /// Key path spend with an optional merkle root for tweaking.
    KeyPath {
        tweak_merkle_root: Option<TapNodeHash>,
    },
    /// Script path spend with control block and tapscript.
    ScriptPath {
        control_block: Vec<u8>,
        script: Vec<u8>,
    },
}

/// Information to re-sign an RBF transaction.
///
/// This can be used for:
/// - **Key path spends**: via `RbfSigningSpendPath::KeyPath`
/// - **Script path spends**: via `RbfSigningSpendPath::ScriptPath`. This only supports scripts that only have a single signature in the witness.
///
/// - Not needed for SinglePlusAnyoneCanPay RBF txs.
/// - Not needed for CPFP.
///
/// Consider adding `#[cfg(any(test, feature = "test-fields"))]` back to
/// `annex` and `additional_taproot_output_count` fields to reduce struct size in production.
/// These fields are only used for testing large transaction scenarios.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbfSigningInfo {
    /// The output index of the UTXO to be re-signed.
    pub vout: u32,
    /// Spend path description (key path or script path).
    pub spend_path: RbfSigningSpendPath,
    /// Taproot sighash type to use when signing.
    pub tap_sighash_type: TapSighashType,
    /// Annex data (used for testing large transaction scenarios).
    pub annex: Option<Vec<u8>>,
    /// Additional taproot output count (used for testing large transaction scenarios).
    pub additional_taproot_output_count: Option<u32>,
}

/// Contains information about the spend path that is needed to sign the utxo.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TapTweakData {
    /// Key path spend with an optional merkle root for tweaking.
    KeyPath(Option<TapNodeHash>),
    /// Script path spend.
    ScriptPath,
    /// Unknown spend path.
    Unknown,
}
