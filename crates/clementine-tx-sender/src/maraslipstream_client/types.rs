use reqwest::StatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

pub(super) const STATUS_SUCCESS: &str = "success";
pub(super) const STATUS_ERROR: &str = "error";

#[derive(Debug, Deserialize)]
pub struct SlipstreamRateInfo {
    pub market_rate: f64,
    pub multiplier: f64,
    pub multiplier_discount_percent: i32,
    pub discounted_multiplier: f64,
    pub submit_fee_rate: f64,
    pub slipstream_rate: f64,
    pub effective_rate: f64,
}

#[derive(Debug, Deserialize)]
pub(super) struct SlipstreamErrorResponse {
    pub is_success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SlipstreamTxSubmitResponse {
    pub status: String,
    // Per Swagger, on success this is a txid string.
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SlipstreamPackageSubmitResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<SlipstreamPackageSubmitResult>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlipstreamApiError {
    pub kind: SlipstreamApiErrorKind,
    pub retryable: bool,
    pub status: StatusCode,
    pub message: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlipstreamApiErrorKind {
    PackageAlreadySubmitted,
    TransactionNotFound,
    BadRequest,
    Unknown,
}

impl SlipstreamPackageSubmitResult {
    pub fn package_rejection(
        &self,
        expected_txids: &[String],
    ) -> Option<SlipstreamPackageRejection> {
        for tx_result in &self.tx_results {
            if let Some(error) = tx_result.error.as_deref() {
                return Some(SlipstreamPackageRejection::TxError {
                    txid: tx_result.txid.clone(),
                    error: error.to_string(),
                });
            }
        }

        if let Some(package_msg) = self.package_msg.as_deref() {
            if !package_msg.eq_ignore_ascii_case(STATUS_SUCCESS) {
                return Some(SlipstreamPackageRejection::PackageMessage(
                    package_msg.to_string(),
                ));
            }
        }

        for txid in expected_txids {
            if !self.tx_results.iter().any(|res| &res.txid == txid) {
                return Some(SlipstreamPackageRejection::MissingTxResult(txid.clone()));
            }
        }

        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SlipstreamPackageRejection {
    TxError { txid: String, error: String },
    PackageMessage(String),
    MissingTxResult(String),
}

impl SlipstreamPackageRejection {
    pub fn is_potentially_idempotent(&self) -> bool {
        !matches!(self, Self::MissingTxResult(_))
    }
}

impl std::fmt::Display for SlipstreamPackageRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxError { txid, error } => write!(f, "txid={txid} error={error}"),
            Self::PackageMessage(msg) => write!(f, "package_msg={msg}"),
            Self::MissingTxResult(txid) => write!(f, "missing tx result for txid {txid}"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamPackageSubmitResult {
    #[serde(default)]
    pub package_msg: Option<String>,
    #[serde(rename = "replaced-transactions", default)]
    pub replaced_transactions: Vec<String>,
    // `tx-results` comes back as an object keyed by an opaque id; the txid to trust is
    // inside each value's `txid` field.
    #[serde(
        rename = "tx-results",
        default,
        deserialize_with = "deserialize_tx_results_values"
    )]
    pub tx_results: Vec<SlipstreamPackageTxResult>,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamPackageTxResult {
    pub txid: String,
    #[serde(rename = "other-wtxid", default)]
    pub other_wtxid: Option<String>,
    pub vsize: Option<u64>,
    #[serde(default)]
    pub fees: Option<SlipstreamPackageTxFees>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamPackageTxFees {
    pub base: Option<f64>,
    #[serde(rename = "effective-feerate")]
    pub effective_feerate: Option<f64>,
    #[serde(rename = "effective-includes", default)]
    pub effective_includes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamTransactionInfo {
    pub message: String,
    pub transaction: SlipstreamTxInfo,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamTxInfo {
    pub txid: String,
}

#[derive(Debug)]
pub enum SlipstreamTransactionStatus {
    Found(SlipstreamTransactionInfo),
    Error {
        message: String,
        api_error: SlipstreamApiError,
    },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum SlipstreamTransactionStatusResponse {
    Found(SlipstreamTransactionInfo),
    Error(SlipstreamErrorResponse),
}

fn deserialize_tx_results_values<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<SlipstreamPackageTxResult>, D::Error>
where
    D: Deserializer<'de>,
{
    let map = HashMap::<String, SlipstreamPackageTxResult>::deserialize(deserializer)?;
    Ok(map.into_values().collect())
}

#[derive(Debug, Serialize)]
pub(super) struct SlipstreamTxSubmitRequest<'a> {
    pub tx_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_code: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub(super) struct SlipstreamPackageSubmitRequest<'a> {
    pub tx_hexes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_code: Option<&'a str>,
}
