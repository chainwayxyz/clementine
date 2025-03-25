use crate::errors::BridgeError;
use clementine::*;
use hyper_util::rt::TokioIo;
use std::path::PathBuf;
use tagged_signature::SignatureId;
use tonic::transport::{Channel, Uri};

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod clementine;

pub mod aggregator;
mod error;
pub mod operator;
 mod parser;
pub mod verifier;
pub mod watchtower;

pub use parser::ParserError;

impl From<NormalSignatureKind> for SignatureId {
    fn from(value: NormalSignatureKind) -> Self {
        SignatureId::NormalSignature(NormalSignatureId {
            signature_kind: value as i32,
        })
    }
}

impl From<(NumberedSignatureKind, i32)> for SignatureId {
    fn from(value: (NumberedSignatureKind, i32)) -> Self {
        SignatureId::NumberedSignature(NumberedSignatureId {
            signature_kind: value.0 as i32,
            idx: value.1,
        })
    }
}

/// Returns gRPC clients.
///
/// # Parameters
///
/// - `endpoints`: URIs for clients (can be http/https URLs or unix:// paths)
/// - `connect`: Function that will be used to initiate gRPC connection
///
/// # Returns
///
/// - [`CLIENT`]: [`tonic`] gRPC client.
pub async fn get_clients<CLIENT, F>(
    endpoints: Vec<String>,
    connect: F,
) -> Result<Vec<CLIENT>, BridgeError>
where
    F: FnOnce(Channel) -> CLIENT + Copy,
{
    futures::future::try_join_all(
        endpoints
            .into_iter()
            .map(|endpoint| async move {
                let channel = if endpoint.starts_with("unix://") {
                    #[cfg(unix)]
                    {
                        // Handle Unix socket (only available on Unix platforms)
                        let path = endpoint.trim_start_matches("unix://").to_string();
                        Channel::from_static("lttp://[::]:50051")
                            .connect_with_connector(tower::service_fn(move |_| {
                                let path = PathBuf::from(path.clone());
                                async move {
                                    let unix_stream = tokio::net::UnixStream::connect(path).await?;
                                    Ok::<_, std::io::Error>(TokioIo::new(unix_stream))
                                }
                            }))
                            .await
                            .map_err(|e| {
                                BridgeError::ConfigError(format!(
                                    "Failed to connect to Unix socket {}: {}",
                                    endpoint, e
                                ))
                            })?
                    }

                    #[cfg(not(unix))]
                    {
                        // Windows doesn't support Unix sockets
                        return Err(BridgeError::ConfigError(format!(
                            "Unix sockets ({}), are not supported on this platform",
                            endpoint
                        )));
                    }
                } else {
                    // Handle TCP/HTTP connection
                    let uri = Uri::try_from(endpoint.clone()).map_err(|e| {
                        BridgeError::ConfigError(format!(
                            "Endpoint {} is malformed: {}",
                            endpoint, e
                        ))
                    })?;

                    Channel::builder(uri).connect().await.map_err(|e| {
                        BridgeError::ConfigError(format!(
                            "Failed to connect to endpoint {}: {}",
                            endpoint, e
                        ))
                    })?
                };

                Ok(connect(channel))
            })
            .collect::<Vec<_>>(),
    )
    .await
}
