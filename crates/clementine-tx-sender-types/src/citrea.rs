//! Citrea-specific tx-sender types.

use serde::{Deserialize, Serialize};

/// Citrea DA payload request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CitreaTxRequest {
    /// borsh(DataOnDa::Complete(compress(Proof)))
    BatchProof {
        bytes: Vec<u8>,
        /// Optional chunk size for splitting large batch proofs.
        /// If omitted or larger than the max supported size, it is clamped.
        chunk_size: Option<u32>,
    },
    /// borsh(DataOnDa::BatchProofMethodId(MethodId))
    BatchProofMethodId(Vec<u8>),
    /// borsh(DataOnDa::SequencerCommitment(SequencerCommitment))
    SequencerCommitment(Vec<u8>),
}

/// Parameters for inserting a Citrea DA transaction request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InsertCitreaRawTxParams {
    /// Opaque DA payload to be inscribed on Bitcoin.
    pub citrea_tx_request: CitreaTxRequest,
}
