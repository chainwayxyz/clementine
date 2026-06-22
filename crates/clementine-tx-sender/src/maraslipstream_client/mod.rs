use crate::maraslipstream::MaraSlipstreamConfig;
use clementine_errors::SendTxError;
use eyre::eyre;
use reqwest::{StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

const SLIPSTREAM_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

mod parser;
mod types;

use parser::{
    parse_rate_response, parse_submit_package_response, parse_submit_tx_response,
    parse_transaction_status_response,
};
pub use types::{
    SlipstreamApiError, SlipstreamApiErrorKind, SlipstreamPackageRejection,
    SlipstreamPackageSubmitResult, SlipstreamRateInfo, SlipstreamTransactionStatus,
};
use types::{SlipstreamPackageSubmitRequest, SlipstreamTxSubmitRequest};

#[derive(Clone)]
pub struct MaraSlipstreamClient {
    http: reqwest::Client,
    get_rate_url: Url,
    submit_tx_url: Url,
    submit_package_url: Url,
    tx_status_url: Url,
}

// Endpoint methods.
impl MaraSlipstreamClient {
    pub fn new(http: reqwest::Client, cfg: &MaraSlipstreamConfig) -> Result<Self, SendTxError> {
        let host = Url::parse(cfg.host.trim_end_matches('/')).map_err(|e| {
            SendTxError::Other(eyre!(e).wrap_err("Slipstream host is not a valid URL"))
        })?;

        Ok(Self {
            http,
            get_rate_url: join(&host, &cfg.fee_rate_endpoint)?,
            submit_tx_url: join(&host, &cfg.submit_tx_endpoint)?,
            submit_package_url: join(&host, &cfg.submit_package_endpoint)?,
            tx_status_url: join(&host, &cfg.tx_status_endpoint)?,
        })
    }

    pub async fn get_rate(
        &self,
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamRateInfo, SendTxError> {
        let mut req = self.http.get(self.get_rate_url.clone());
        if let Some(code) = client_code {
            req = req.query(&[("client_code", code.expose_secret())]);
        }

        let (status, body) = send_read_text(req).await?;

        parse_rate_response(status, &body)
    }

    pub async fn submit_tx(
        &self,
        tx_hex: &str,
        client_code: Option<&SecretString>,
    ) -> Result<bitcoin::Txid, SendTxError> {
        let req_body = SlipstreamTxSubmitRequest {
            tx_hex,
            client_code: client_code.map(ExposeSecret::expose_secret),
        };

        let req = self.http.post(self.submit_tx_url.clone()).json(&req_body);
        let (status, body) = send_read_text(req).await?;

        parse_submit_tx_response(status, &body)
    }

    pub async fn submit_package(
        &self,
        tx_hexes: &[String],
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamPackageSubmitResult, SendTxError> {
        let req_body = SlipstreamPackageSubmitRequest {
            tx_hexes,
            client_code: client_code.map(ExposeSecret::expose_secret),
        };

        let req = self
            .http
            .post(self.submit_package_url.clone())
            .json(&req_body);
        let (status, body) = send_read_text(req).await?;

        parse_submit_package_response(status, &body)
    }

    pub async fn transaction_status(
        &self,
        txid: &str,
    ) -> Result<SlipstreamTransactionStatus, SendTxError> {
        let req = self
            .http
            .get(self.tx_status_url.clone())
            .query(&[("tx_id", txid)]);
        let (status, body) = send_read_text(req).await?;

        parse_transaction_status_response(status, &body, txid)
    }

    pub async fn transaction_found(&self, txid: &str) -> Result<bool, SendTxError> {
        match self.transaction_status(txid).await? {
            SlipstreamTransactionStatus::Found(status) => Ok(status.transaction.txid == txid),
            SlipstreamTransactionStatus::Error { api_error, .. }
                if matches!(api_error.kind, SlipstreamApiErrorKind::TransactionNotFound) =>
            {
                Ok(false)
            }
            SlipstreamTransactionStatus::Error { api_error, .. } => Err(SendTxError::Other(eyre!(
                "Slipstream transaction-status HTTP {} ({:?}, retryable={}): {}",
                api_error.status,
                api_error.kind,
                api_error.retryable,
                api_error.message.as_deref().unwrap_or(&api_error.raw)
            ))),
        }
    }
}

// HTTP helpers.
fn join(host: &Url, endpoint: &str) -> Result<Url, SendTxError> {
    let endpoint = if endpoint.starts_with('/') {
        endpoint.to_owned()
    } else {
        format!("/{endpoint}")
    };

    host.join(&endpoint).map_err(|e| {
        SendTxError::Other(eyre!(e).wrap_err("Failed to join Slipstream endpoint URL"))
    })
}

async fn send_read_text(req: reqwest::RequestBuilder) -> Result<(StatusCode, String), SendTxError> {
    let resp = tokio::time::timeout(SLIPSTREAM_HTTP_TIMEOUT, req.send())
        .await
        .map_err(|_| SendTxError::NetworkError("Slipstream request timed out".to_string()))?
        .map_err(|e| SendTxError::NetworkError(format!("Slipstream request failed: {e}")))?;

    let status = resp.status();
    let body = tokio::time::timeout(SLIPSTREAM_HTTP_TIMEOUT, resp.text())
        .await
        .map_err(|_| {
            SendTxError::NetworkError("Slipstream reading response body timed out".to_string())
        })?
        .map_err(|e| {
            SendTxError::NetworkError(format!("Slipstream failed reading response body: {e}"))
        })?;
    Ok((status, body))
}
