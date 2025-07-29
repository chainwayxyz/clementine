use crate::errors::BridgeError;
use clementine::*;
use eyre::Context;
use hyper_util::rt::TokioIo;
use std::path::PathBuf;
use tagged_signature::SignatureId;
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri},
    Status,
};

#[cfg(test)]
use crate::test::common::ensure_test_certificates;

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod clementine;

pub mod aggregator;
mod error;
pub mod interceptors;
pub mod operator;
mod parser;
pub mod verifier;

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
/// - `config`: Configuration containing TLS certificate paths
///
/// # Returns
///
/// - [`CLIENT`]: [`tonic`] gRPC client.
pub async fn get_clients<CLIENT, F>(
    endpoints: Vec<String>,
    connect: F,
    config: &crate::config::BridgeConfig,
    use_client_cert: bool,
) -> Result<Vec<CLIENT>, BridgeError>
where
    F: FnOnce(Channel) -> CLIENT + Copy,
{
    // Ensure certificates exist in test mode
    #[cfg(test)]
    {
        ensure_test_certificates().map_err(|e| {
            BridgeError::ConfigError(format!("Failed to ensure test certificates: {}", e))
        })?;
    }

    // Get certificate paths from config or use defaults
    let client_ca_cert = tokio::fs::read(&config.ca_cert_path)
        .await
        .wrap_err(format!(
            "Failed to read CA certificate from {}",
            config.ca_cert_path.display()
        ))?;

    let client_ca = Certificate::from_pem(client_ca_cert);

    // Get certificate paths from config or use defaults
    let client_cert_path = &config.client_cert_path.clone();
    let client_key_path = &config.client_key_path.clone();

    // Load client certificate and key
    let client_cert = tokio::fs::read(&client_cert_path).await.map_err(|e| {
        BridgeError::ConfigError(format!(
            "Failed to read client certificate from {}: {}",
            client_cert_path.display(),
            e
        ))
    })?;

    let client_key = tokio::fs::read(&client_key_path).await.map_err(|e| {
        BridgeError::ConfigError(format!(
            "Failed to read client key from {}: {}",
            client_key_path.display(),
            e
        ))
    })?;

    futures::future::try_join_all(
        endpoints
            .into_iter()
            .map(|endpoint| {
                let client_cert = client_cert.clone();
                let client_key = client_key.clone();
                let client_ca = client_ca.clone();

                let tls_config = if use_client_cert {
                    let client_identity = Identity::from_pem(client_cert, client_key);
                    ClientTlsConfig::new()
                        .identity(client_identity)
                        .ca_certificate(client_ca)
                } else {
                    ClientTlsConfig::new().ca_certificate(client_ca)
                };

                async move {
                    let channel = if endpoint.starts_with("unix://") {
                        #[cfg(unix)]
                        {
                            // Handle Unix socket (only available on Unix platforms)
                            let path = endpoint.trim_start_matches("unix://").to_string();
                            Channel::from_static("lttp://[::]:50051")
                                .connect_with_connector(tower::service_fn(move |_| {
                                    let path = PathBuf::from(path.clone());
                                    async move {
                                        let unix_stream =
                                            tokio::net::UnixStream::connect(path).await?;
                                        Ok::<_, std::io::Error>(TokioIo::new(unix_stream))
                                    }
                                }))
                                .await
                                .wrap_err_with(|| {
                                    format!("Failed to connect to Unix socket {}", endpoint)
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

                        Channel::builder(uri)
                            .tls_config(tls_config)
                            .wrap_err("Failed to configure TLS")?
                            .connect()
                            .await
                            .wrap_err("Failed to connect to endpoint")?
                    };

                    Ok(connect(channel))
                }
            })
            .collect::<Vec<_>>(),
    )
    .await
}
