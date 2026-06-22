//! Clementine-specific tx-sender types.

use serde::{Deserialize, Serialize};

use bitcoin::{OutPoint, TapNodeHash, TapSighashType, Txid, XOnlyPublicKey};
use clementine_primitives::{RoundIndex, TransactionType};

/// Activation condition based on a transaction ID.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActivatedWithTxid {
    /// The transaction ID that must be seen.
    pub txid: Txid,
    /// Number of blocks that must pass after seeing the transaction.
    pub relative_block_height: u32,
}

/// Specifies the fee bumping strategy used for a transaction.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "fee_paying_type", rename_all = "lowercase")
)]
pub enum FeePayingType {
    /// Child-Pays-For-Parent: A new "child" transaction is created, spending an output
    /// from the original "parent" transaction. The child pays a high fee, sufficient
    /// to cover both its own cost and the parent's fee deficit, incentivizing miners
    /// to confirm both together. Specifically, we utilize "fee payer" UTXOs.
    CPFP,
    /// Replace-By-Fee: The original unconfirmed transaction is replaced with a new
    /// version that includes a higher fee. The original transaction must signal
    /// RBF enablement (e.g., via nSequence). Bitcoin Core's `bumpfee` RPC is often used.
    RBF,
    /// Replace-By-Fee (wtxid grind): Like RBF, but the transaction is re-signed / mutated
    /// as needed to achieve a desired wtxid prefix. This option will grind by changing the transaction locktime,
    /// so ensure that any transaction that uses this do not require a specific locktime.
    #[cfg_attr(feature = "sqlx", sqlx(rename = "rbf_wtxid_grind"))]
    RbfWtxidGrind,
    /// The transaction has already been funded and no fee is needed.
    /// Currently used for disprove tx as it has operator's collateral as input.
    NoFunding,
}

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
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbfSigningInfo {
    /// The output index of the UTXO to be re-signed.
    pub vout: u32,
    /// Spend path description (key path or script path).
    pub spend_path: RbfSigningSpendPath,
    /// Taproot sighash type to use when signing.
    pub tap_sighash_type: TapSighashType,
    /// Annex data (used for testing large transaction scenarios).
    #[cfg(feature = "test-fields")]
    pub annex: Option<Vec<u8>>,
    /// Additional taproot output count (used for testing large transaction scenarios).
    #[cfg(feature = "test-fields")]
    pub additional_taproot_output_count: Option<u32>,
}

impl RbfSigningInfo {
    pub fn new(
        vout: u32,
        spend_path: RbfSigningSpendPath,
        tap_sighash_type: TapSighashType,
    ) -> Self {
        Self {
            vout,
            spend_path,
            tap_sighash_type,
            #[cfg(feature = "test-fields")]
            annex: None,
            #[cfg(feature = "test-fields")]
            additional_taproot_output_count: None,
        }
    }

    #[cfg(feature = "test-fields")]
    pub fn with_annex(mut self, annex: Option<Vec<u8>>) -> Self {
        self.annex = annex;
        self
    }

    #[cfg(feature = "test-fields")]
    pub fn with_additional_taproot_output_count(mut self, count: Option<u32>) -> Self {
        self.additional_taproot_output_count = count;
        self
    }
}

/// Metadata about a transaction.
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxMetadata {
    /// The deposit outpoint associated with this transaction.
    pub deposit_outpoint: Option<OutPoint>,
    /// The operator's X-only public key.
    pub operator_xonly_pk: Option<XOnlyPublicKey>,
    /// The round index for this transaction.
    pub round_idx: Option<RoundIndex>,
    /// The kickoff index for this transaction.
    pub kickoff_idx: Option<u32>,
    /// The type of transaction.
    pub tx_type: TransactionType,
}

impl std::fmt::Debug for TxMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg_struct = f.debug_struct("TxMetadata");
        if let Some(deposit_outpoint) = self.deposit_outpoint {
            dbg_struct.field("deposit_outpoint", &deposit_outpoint);
        }
        if let Some(operator_xonly_pk) = self.operator_xonly_pk {
            dbg_struct.field("operator_xonly_pk", &operator_xonly_pk);
        }
        if let Some(round_idx) = self.round_idx {
            dbg_struct.field("round_idx", &round_idx);
        }
        if let Some(kickoff_idx) = self.kickoff_idx {
            dbg_struct.field("kickoff_idx", &kickoff_idx);
        }
        dbg_struct.field("tx_type", &self.tx_type);
        dbg_struct.finish()
    }
}

/// Parameters for inserting a transaction into the tx-sender queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertTryToSendParams {
    pub tx_metadata: Option<TxMetadata>,
    /// Signed tx encoded as hex.
    pub signed_tx_hex: String,
    pub fee_paying_type: FeePayingType,
    pub rbf_signing_info: Option<RbfSigningInfo>,
    pub activate_txids: Vec<ActivatedWithTxid>,
}
