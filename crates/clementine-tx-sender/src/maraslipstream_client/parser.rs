use super::types::{
    SlipstreamApiError, SlipstreamApiErrorKind, SlipstreamErrorResponse,
    SlipstreamPackageSubmitResponse, SlipstreamPackageSubmitResult, SlipstreamRateInfo,
    SlipstreamTransactionStatus, SlipstreamTransactionStatusResponse, SlipstreamTxSubmitResponse,
    STATUS_ERROR, STATUS_SUCCESS,
};
use bitcoin::Txid;
use clementine_errors::SendTxError;
use eyre::eyre;
use reqwest::StatusCode;
use serde::Deserialize;

// Mara does not expose an error code for this; update if the response text changes.
const PACKAGE_ALREADY_SUBMITTED_MSG: &str = "Your transactions already submitted";
const TRANSACTION_NOT_FOUND_MSG: &str = "Transaction not found";

#[derive(Clone, Copy)]
enum SlipstreamOperation {
    GetRate,
    SubmitTx,
    SubmitPackage,
    TransactionStatus,
}

impl SlipstreamOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::GetRate => "getrate",
            Self::SubmitTx => "submit-tx",
            Self::SubmitPackage => "submit-package",
            Self::TransactionStatus => "transaction-status",
        }
    }
}

pub(super) fn parse_rate_response(
    status: StatusCode,
    body: &str,
) -> Result<SlipstreamRateInfo, SendTxError> {
    if status.is_success() {
        return serde_json::from_str(body)
            .map_err(|e| SendTxError::Other(eyre!(e).wrap_err("Slipstream getrate invalid JSON")));
    }

    Err(parse_endpoint_error(
        SlipstreamOperation::GetRate,
        status,
        body,
    ))
}

pub(super) fn parse_submit_tx_response(
    status: StatusCode,
    body: &str,
) -> Result<Txid, SendTxError> {
    if !status.is_success() {
        return Err(parse_endpoint_error(
            SlipstreamOperation::SubmitTx,
            status,
            body,
        ));
    }

    let res: SlipstreamTxSubmitResponse = serde_json::from_str(body)
        .map_err(|e| SendTxError::Other(eyre!(e).wrap_err("Slipstream submit-tx invalid JSON")))?;

    if res.status.eq_ignore_ascii_case(STATUS_SUCCESS) {
        return res.message.parse::<Txid>().map_err(|e| {
            SendTxError::Other(eyre!(e).wrap_err(format!(
                "Slipstream submit-tx returned invalid txid: {}",
                res.message
            )))
        });
    }

    if res.status.eq_ignore_ascii_case(STATUS_ERROR) {
        return Err(parse_endpoint_error(
            SlipstreamOperation::SubmitTx,
            status,
            body,
        ));
    }

    Err(unexpected_response_body(
        SlipstreamOperation::SubmitTx,
        status,
        body,
    ))
}

pub(super) fn parse_submit_package_response(
    status: StatusCode,
    body: &str,
) -> Result<SlipstreamPackageSubmitResult, SendTxError> {
    if !status.is_success() {
        return Err(parse_endpoint_error(
            SlipstreamOperation::SubmitPackage,
            status,
            body,
        ));
    }

    let res: SlipstreamPackageSubmitResponse = serde_json::from_str(body).map_err(|e| {
        SendTxError::Other(eyre!(e).wrap_err("Slipstream submit-package invalid JSON"))
    })?;

    if res.status.eq_ignore_ascii_case(STATUS_SUCCESS) {
        return res.result.ok_or_else(|| {
            SendTxError::Other(eyre!(
                "Slipstream submit-package success response missing result"
            ))
        });
    }

    if res.status.eq_ignore_ascii_case(STATUS_ERROR) && res.error.is_some() {
        return Err(parse_endpoint_error(
            SlipstreamOperation::SubmitPackage,
            status,
            body,
        ));
    }

    Err(unexpected_response_body(
        SlipstreamOperation::SubmitPackage,
        status,
        body,
    ))
}

pub(super) fn parse_transaction_status_response(
    status: StatusCode,
    body: &str,
    txid: &str,
) -> Result<SlipstreamTransactionStatus, SendTxError> {
    match serde_json::from_str::<SlipstreamTransactionStatusResponse>(body) {
        Ok(SlipstreamTransactionStatusResponse::Found(res)) if status.is_success() => {
            Ok(SlipstreamTransactionStatus::Found(res))
        }
        Ok(SlipstreamTransactionStatusResponse::Error(err)) => {
            let api_error = classify_api_error(status, body);
            Ok(SlipstreamTransactionStatus::Error {
                message: err.message,
                api_error,
            })
        }
        Ok(SlipstreamTransactionStatusResponse::Found(_)) => Err(unexpected_response_body(
            SlipstreamOperation::TransactionStatus,
            status,
            body,
        )),
        Err(e) if status.is_success() => {
            tracing::warn!(
                txid,
                "Slipstream transaction status response JSON parse error: {e:?}; body was: {body}"
            );
            Err(SendTxError::Other(
                eyre!(e).wrap_err("Slipstream transaction status invalid JSON"),
            ))
        }
        Err(_) => Err(parse_endpoint_error(
            SlipstreamOperation::TransactionStatus,
            status,
            body,
        )),
    }
}

fn classify_api_error(status: StatusCode, body: &str) -> SlipstreamApiError {
    let message = extract_error_message(body);
    let kind = match (status, message.as_deref()) {
        (StatusCode::BAD_REQUEST, Some(PACKAGE_ALREADY_SUBMITTED_MSG)) => {
            SlipstreamApiErrorKind::PackageAlreadySubmitted
        }
        (StatusCode::BAD_REQUEST, Some(TRANSACTION_NOT_FOUND_MSG)) => {
            SlipstreamApiErrorKind::TransactionNotFound
        }
        (StatusCode::BAD_REQUEST, _) => SlipstreamApiErrorKind::BadRequest,
        _ => SlipstreamApiErrorKind::Unknown,
    };
    let retryable = matches!(kind, SlipstreamApiErrorKind::Unknown) && status.is_server_error();

    SlipstreamApiError {
        kind,
        retryable,
        status,
        message,
        raw: body.to_string(),
    }
}

fn extract_error_message(body: &str) -> Option<String> {
    match serde_json::from_str::<SlipstreamErrorBody>(body).ok()? {
        SlipstreamErrorBody::Standard(err) if !err.is_success => Some(err.message),
        SlipstreamErrorBody::TxSubmit(err) if err.status.eq_ignore_ascii_case(STATUS_ERROR) => {
            Some(err.message)
        }
        SlipstreamErrorBody::PackageSubmit(err)
            if err.status.eq_ignore_ascii_case(STATUS_ERROR) =>
        {
            err.error
        }
        _ => None,
    }
}

fn parse_endpoint_error(op: SlipstreamOperation, status: StatusCode, body: &str) -> SendTxError {
    api_error_to_send_tx_error(op, classify_api_error(status, body))
}

fn api_error_to_send_tx_error(op: SlipstreamOperation, err: SlipstreamApiError) -> SendTxError {
    if matches!(err.kind, SlipstreamApiErrorKind::PackageAlreadySubmitted) {
        return SendTxError::SlipstreamPackageAlreadySubmitted;
    }

    let detail = err.message.as_deref().unwrap_or(&err.raw);
    let op = op.as_str();
    SendTxError::Other(eyre!(
        "Slipstream {op} HTTP {} ({:?}, retryable={}): {detail}",
        err.status,
        err.kind,
        err.retryable
    ))
}

fn unexpected_response_body(
    op: SlipstreamOperation,
    status: StatusCode,
    body: &str,
) -> SendTxError {
    let op = op.as_str();
    SendTxError::Other(eyre!("Slipstream {op} HTTP {status}: {body}"))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SlipstreamErrorBody {
    Standard(SlipstreamErrorResponse),
    TxSubmit(SlipstreamTxSubmitResponse),
    PackageSubmit(SlipstreamPackageSubmitResponse),
}