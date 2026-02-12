use crate::maraslipstream::MaraSlipstreamConfig;
use clementine_errors::SendTxError;
use eyre::eyre;
use reqwest::{StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::time::Duration;

const SLIPSTREAM_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct MaraSlipstreamClient {
    http: reqwest::Client,
    get_rate_url: Url,
    submit_tx_url: Url,
    submit_package_url: Url,
}

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
        })
    }

    pub async fn get_rate_with_fallback(
        &self,
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamRateInfo, SendTxError> {
        match self.get_rate(client_code).await {
            Ok(res) => Ok(res),
            Err(e) if is_invalid_client_code_msg(&e.to_string()) => self.get_rate(None).await,
            Err(e) => Err(e),
        }
    }

    pub async fn submit_tx_with_fallback(
        &self,
        tx_hex: &str,
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamTxSubmitResponse, SendTxError> {
        match self.submit_tx(tx_hex, client_code).await {
            Ok(res) => Ok(res),
            Err(e) if is_invalid_client_code_msg(&e.to_string()) => {
                self.submit_tx(tx_hex, None).await
            }
            Err(e) => Err(e),
        }
    }

    pub async fn submit_package_with_fallback(
        &self,
        tx_hexes: &[String],
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamPackageSubmitResponse, SendTxError> {
        match self.submit_package(tx_hexes, client_code).await {
            Ok(res) => Ok(res),
            Err(e) if is_invalid_client_code_msg(&e.to_string()) => {
                self.submit_package(tx_hexes, None).await
            }
            Err(e) => Err(e),
        }
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
        if status.is_success() {
            let res: SlipstreamRateInfo = serde_json::from_str(&body).map_err(|e| {
                SendTxError::Other(eyre!(e).wrap_err("Slipstream getrate invalid JSON"))
            })?;
            return Ok(res);
        }

        Err(map_slipstream_error(status, &body, "getrate"))
    }

    pub async fn submit_tx(
        &self,
        tx_hex: &str,
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamTxSubmitResponse, SendTxError> {
        let req_body = SlipstreamTxSubmitRequest {
            tx_hex,
            client_code: client_code.map(ExposeSecret::expose_secret),
        };

        let req = self.http.post(self.submit_tx_url.clone()).json(&req_body);
        let (status, body) = send_read_text(req).await?;

        // The API returns a JSON response body even for 400s.
        let res: SlipstreamTxSubmitResponse = serde_json::from_str(&body).map_err(|e| {
            SendTxError::Other(eyre!(e).wrap_err("Slipstream submit-tx invalid JSON"))
        })?;

        if status.is_success() && res.status.eq_ignore_ascii_case("success") {
            Ok(res)
        } else {
            Err(map_slipstream_error(status, &body, "submit-tx"))
        }
    }

    pub async fn submit_package(
        &self,
        tx_hexes: &[String],
        client_code: Option<&SecretString>,
    ) -> Result<SlipstreamPackageSubmitResponse, SendTxError> {
        let req_body = SlipstreamPackageSubmitRequest {
            tx_hexes,
            client_code: client_code.map(ExposeSecret::expose_secret),
        };

        let req = self
            .http
            .post(self.submit_package_url.clone())
            .json(&req_body);
        let (status, body) = send_read_text(req).await?;

        // The API returns a JSON response body even for 400s.
        let res: SlipstreamPackageSubmitResponse = serde_json::from_str(&body).map_err(|e| {
            SendTxError::Other(eyre!(e).wrap_err("Slipstream submit-package invalid JSON"))
        })?;

        if status.is_success() && res.status.eq_ignore_ascii_case("success") {
            Ok(res)
        } else {
            Err(map_slipstream_error(status, &body, "submit-package"))
        }
    }
}

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

fn map_slipstream_error(status: StatusCode, body: &str, op: &str) -> SendTxError {
    // For getrate, invalid client codes return:
    // {"is_success":false,"message":"Requested client code is invalid"}
    if let Ok(err) = serde_json::from_str::<SlipstreamErrorResponse>(body) {
        return SendTxError::Other(eyre!("Slipstream {op} HTTP {status}: {}", err.message));
    }

    // For submit endpoints, errors may be:
    // {"status":"error","message":"..."}
    if let Ok(err) = serde_json::from_str::<SlipstreamTxSubmitResponse>(body) {
        if err.status.eq_ignore_ascii_case("error") {
            return SendTxError::Other(eyre!("Slipstream {op} HTTP {status}: {}", err.message));
        }
    }

    if let Ok(err) = serde_json::from_str::<SlipstreamPackageSubmitResponse>(body) {
        if err.status.eq_ignore_ascii_case("error") {
            if let Some(msg) = err.error {
                return SendTxError::Other(eyre!("Slipstream {op} HTTP {status}: {msg}"));
            }
        }
    }

    SendTxError::Other(eyre!("Slipstream {op} HTTP {status}: {body}"))
}

fn is_invalid_client_code_msg(msg: &str) -> bool {
    // Keep matching flexible across endpoints/wording.
    let m = msg.to_ascii_lowercase();
    m.contains("client code") && m.contains("invalid")
}

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
pub struct SlipstreamErrorResponse {
    pub is_success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamTxSubmitResponse {
    pub status: String,
    // Per Swagger, on success this is a txid string.
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamPackageSubmitResponse {
    pub status: String,
    #[serde(default)]
    pub result: Option<SlipstreamPackageSubmitResult>,
    #[serde(default)]
    pub error: Option<String>,
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
    pub vsize: Option<u64>,
    #[serde(default)]
    pub fees: Option<SlipstreamPackageTxFees>,
}

#[derive(Debug, Deserialize)]
pub struct SlipstreamPackageTxFees {
    pub base: Option<f64>,
    #[serde(rename = "effective-feerate")]
    pub effective_feerate: Option<f64>,
    #[serde(rename = "effective-includes", default)]
    pub effective_includes: Vec<String>,
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
struct SlipstreamTxSubmitRequest<'a> {
    pub tx_hex: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_code: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct SlipstreamPackageSubmitRequest<'a> {
    pub tx_hexes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_code: Option<&'a str>,
}
