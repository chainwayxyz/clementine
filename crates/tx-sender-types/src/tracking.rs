//! Shared tracking types for tx-sender JSON-RPC.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrackRequest {
    TryToSend { try_to_send_id: u32 },
    ByTxid { txid: String },
    Citrea { insertion_id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackStatus {
    Pending,
    InProgress,
    Mined,
    Finalized,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrackResponse {
    Submission(SubmissionStatus),
    Citrea(CitreaStatus),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTxStatus {
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mined_at_height: Option<u32>,
    pub in_mempool: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionStatus {
    pub status: TrackStatus,
    pub activation: ActivationState,
    pub tx_info: BitcoinTxStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_sat_kvb: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fee_payer_txs: Vec<BitcoinTxStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitreaStatus {
    pub status: TrackStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_tx: Option<BitcoinTxStatus>,
    pub reveals: Vec<CitreaRevealStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_commit_tx: Option<BitcoinTxStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_reveal_submission: Option<SubmissionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitreaRevealStatus {
    pub kind: CitreaTxKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submission: Option<SubmissionStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CitreaTxKind {
    Complete,
    Chunk,
    BatchProofMethodId,
    SequencerCommitment,
    Aggregate,
    Unknown(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationState {
    Active,
    Waiting { blockers: Vec<ActivationBlocker> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationBlocker {
    pub txid: String,
    pub reason: ActivationBlockerReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationBlockerReason {
    Missing,
    Timelocked {
        mined_at_height: u32,
        required_blocks: u32,
        remaining_blocks: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_response_roundtrip() {
        let value = TrackResponse::Submission(SubmissionStatus {
            status: TrackStatus::InProgress,
            activation: ActivationState::Waiting {
                blockers: vec![ActivationBlocker {
                    txid: "abc".into(),
                    reason: ActivationBlockerReason::Missing,
                }],
            },
            tx_info: BitcoinTxStatus {
                txid: "deadbeef".into(),
                mined_at_height: None,
                in_mempool: true,
            },
            fee_sat_kvb: Some(2500),
            fee_payer_txs: vec![],
            last_error: None,
        });

        let encoded = serde_json::to_string(&value).expect("tracking response should serialize");
        let decoded: TrackResponse =
            serde_json::from_str(&encoded).expect("tracking response should deserialize");

        match decoded {
            TrackResponse::Submission(track) => {
                assert_eq!(track.status, TrackStatus::InProgress);
            }
            TrackResponse::Citrea(_) => panic!("expected Submission variant"),
        }
    }
}
