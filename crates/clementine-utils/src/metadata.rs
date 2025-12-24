//! Transaction metadata types.

use bitcoin::{OutPoint, XOnlyPublicKey};
use clementine_primitives::{RoundIndex, TransactionType};
use serde::{Deserialize, Serialize};

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
