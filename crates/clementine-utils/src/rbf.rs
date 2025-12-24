//! RBF (Replace-By-Fee) signing information.

use bitcoin::TapNodeHash;
use serde::{Deserialize, Serialize};

/// Information to re-sign an RBF transaction.
/// Specifically the merkle root of the taproot to keyspend with and the output index of the utxo to be
/// re-signed.
///
/// - Not needed for SinglePlusAnyoneCanPay RBF txs.
/// - Not needed for CPFP.
/// - Only signs for a keypath spend
// TODO(perf): Consider adding `#[cfg(any(test, feature = "test-fields"))]` back to
// `annex` and `additional_taproot_output_count` fields to reduce struct size in production.
// These fields are only used for testing large transaction scenarios.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbfSigningInfo {
    /// The output index of the UTXO to be re-signed.
    pub vout: u32,
    /// The tweak merkle root for the taproot keyspend.
    pub tweak_merkle_root: Option<TapNodeHash>,
    /// Annex data (used for testing large transaction scenarios).
    pub annex: Option<Vec<u8>>,
    /// Additional taproot output count (used for testing large transaction scenarios).
    pub additional_taproot_output_count: Option<u32>,
}
