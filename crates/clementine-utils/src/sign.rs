//! Signing information for taproot spends.

use bitcoin::TapNodeHash;
use serde::{Deserialize, Serialize};

/// Information to re-sign an RBF transaction.
/// Specifically the merkle root of the taproot to keyspend with and the output index of the utxo to be
/// re-signed.
///
/// - Not needed for SinglePlusAnyoneCanPay RBF txs.
/// - Not needed for CPFP.
/// - Only signs for a keypath spend
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbfSigningInfo {
    /// The output index of the UTXO to be re-signed.
    pub vout: u32,
    /// The tweak merkle root for the taproot keyspend.
    pub tweak_merkle_root: Option<TapNodeHash>,
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
