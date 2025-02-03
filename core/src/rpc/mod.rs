use crate::errors::BridgeError;
use std::future::Future;
use tonic::transport::Uri;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod clementine;

pub mod aggregator;
mod error;
pub mod operator;
mod parser;
pub mod verifier;
pub mod watchtower;
mod wrapper;

/// Returns gRPC clients.
///
/// # Parameters
///
/// - `endpoints`: URIs for clients
/// - `connect`: Function that will be used to initiate gRPC connection
///
/// # Returns
///
/// - [`CLIENT`]: [`tonic`] gRPC client.
pub async fn get_clients<CLIENT, F, Fut>(
    endpoints: Vec<String>,
    connect: F,
) -> Result<Vec<CLIENT>, BridgeError>
where
    F: FnOnce(Uri) -> Fut + Copy,
    Fut: Future<Output = Result<CLIENT, tonic::transport::Error>>,
{
    futures::future::try_join_all(endpoints.iter().map(|endpoint| async move {
        let uri = Uri::try_from(endpoint).map_err(|e| {
            BridgeError::ConfigError(format!("Endpoint {} is malformed: {}", endpoint, e))
        })?;

        Ok(connect(uri).await?)
    }))
    .await
}
