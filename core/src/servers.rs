//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::aggregator::AggregatorServer;
use crate::citrea::CitreaClientT;
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::operator::OperatorServer;
use crate::rpc::clementine::clementine_aggregator_server::ClementineAggregatorServer;
use crate::rpc::clementine::clementine_operator_server::ClementineOperatorServer;
use crate::rpc::clementine::clementine_verifier_server::ClementineVerifierServer;
use crate::rpc::interceptors::Interceptors::{Noop, OnlyAggregatorAndSelf};
use crate::utils::AddMethodMiddlewareLayer;
use crate::verifier::VerifierServer;
use crate::{config::BridgeConfig, errors};
use errors::BridgeError;
use eyre::Context;
use rustls_pki_types::pem::PemObject;
use std::time::Duration;
use tokio::sync::oneshot;
use tonic::server::NamedService;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, CertificateDer, Identity, ServerTlsConfig};
use tower::buffer::BufferLayer;
use tower::limit::RateLimitLayer;

#[cfg(test)]
use crate::test::common::ensure_test_certificates;

pub type ServerFuture = dyn futures::Future<Output = Result<(), tonic::transport::Error>>;

/// Represents a network address that can be either TCP or Unix socket
#[derive(Debug, Clone)]
pub enum ServerAddr {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl From<std::net::SocketAddr> for ServerAddr {
    fn from(addr: std::net::SocketAddr) -> Self {
        ServerAddr::Tcp(addr)
    }
}

#[cfg(unix)]
impl From<std::path::PathBuf> for ServerAddr {
    fn from(path: std::path::PathBuf) -> Self {
        ServerAddr::Unix(path)
    }
}

/// Generic function to create a gRPC server with the given service
pub async fn create_grpc_server<S>(
    addr: ServerAddr,
    service: S,
    server_name: &str,
    config: &BridgeConfig,
) -> Result<(ServerAddr, oneshot::Sender<()>), BridgeError>
where
    S: tower::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + NamedService
        + 'static,
    S::Future: Send + 'static,
{
    // Create channels for server readiness and shutdown
    let (ready_tx, ready_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // Ensure certificates exist in test mode
    #[cfg(test)]
    {
        ensure_test_certificates().wrap_err("Failed to ensure test certificates")?;
    }

    match addr {
        ServerAddr::Tcp(socket_addr) => {
            let cert = tokio::fs::read(&config.server_cert_path)
                .await
                .wrap_err(format!(
                    "Failed to read server certificate from {}",
                    config.server_cert_path.display()
                ))?;
            let key = tokio::fs::read(&config.server_key_path)
                .await
                .wrap_err(format!(
                    "Failed to read server key from {}",
                    config.server_key_path.display()
                ))?;

            let server_identity = Identity::from_pem(cert, key);

            // Load CA certificate for client verification
            let client_ca_cert = tokio::fs::read(&config.ca_cert_path)
                .await
                .wrap_err(format!(
                    "Failed to read CA certificate from {}",
                    config.ca_cert_path.display()
                ))?;

            let client_ca = Certificate::from_pem(client_ca_cert);

            // Build TLS configuration
            let tls_config = if config.client_verification {
                ServerTlsConfig::new()
                    .identity(server_identity)
                    .client_ca_root(client_ca)
            } else {
                ServerTlsConfig::new().identity(server_identity)
            };

            let service = InterceptedService::new(
                service,
                if config.client_verification {
                    let client_cert = CertificateDer::from_pem_file(&config.client_cert_path)
                        .wrap_err(format!(
                            "Failed to read client certificate from {}",
                            config.client_cert_path.display()
                        ))?
                        .to_owned();

                    let aggregator_cert =
                        CertificateDer::from_pem_file(&config.aggregator_cert_path)
                            .wrap_err(format!(
                                "Failed to read aggregator certificate from {}",
                                config.aggregator_cert_path.display()
                            ))?
                            .to_owned();

                    OnlyAggregatorAndSelf {
                        aggregator_cert,
                        our_cert: client_cert,
                    }
                } else {
                    Noop
                },
            );

            tracing::info!(
                "Starting {} gRPC server with TCP address: {}",
                server_name,
                socket_addr
            );

            let server_builder = tonic::transport::Server::builder()
                .layer(AddMethodMiddlewareLayer)
                .layer(BufferLayer::new(config.grpc.req_concurrency_limit))
                .layer(RateLimitLayer::new(
                    config.grpc.ratelimit_req_count as u64,
                    Duration::from_secs(config.grpc.ratelimit_req_interval_secs),
                ))
                .timeout(Duration::from_secs(config.grpc.timeout_secs))
                .tcp_keepalive(Some(Duration::from_secs(config.grpc.tcp_keepalive_secs)))
                .concurrency_limit_per_connection(config.grpc.req_concurrency_limit)
                .http2_adaptive_window(Some(true))
                .tls_config(tls_config)
                .wrap_err("Failed to configure TLS")?
                .add_service(service);

            let server_name_str = server_name.to_string();

            let handle = server_builder.serve_with_shutdown(socket_addr, async move {
                let _ = ready_tx.send(());
                shutdown_rx.await.ok();
                tracing::info!("{} gRPC server shutting down", server_name_str);
            });

            let server_name_str = server_name.to_string();

            tokio::spawn(async move {
                if let Err(e) = handle.await {
                    tracing::error!("{} gRPC server error: {:?}", server_name_str, e);
                }
            });
        }
        #[cfg(unix)]
        ServerAddr::Unix(ref socket_path) => {
            let server_builder = tonic::transport::Server::builder()
                .layer(AddMethodMiddlewareLayer)
                .layer(BufferLayer::new(config.grpc.req_concurrency_limit))
                .layer(RateLimitLayer::new(
                    config.grpc.ratelimit_req_count as u64,
                    Duration::from_secs(config.grpc.ratelimit_req_interval_secs),
                ))
                .timeout(Duration::from_secs(config.grpc.timeout_secs))
                .concurrency_limit_per_connection(config.grpc.req_concurrency_limit)
                .add_service(service);
            tracing::info!(
                "Starting {} gRPC server with Unix socket: {:?}",
                server_name,
                socket_path
            );

            // Remove socket file if it already exists
            if socket_path.exists() {
                std::fs::remove_file(socket_path)
                    .wrap_err("Failed to remove existing gRPC unix socket file")?;
            }

            // Create Unix socket listener
            let uds = tokio::net::UnixListener::bind(socket_path)
                .wrap_err("Failed to bind to Unix socket")?;
            let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

            let server_name_str = server_name.to_string();

            let handle = server_builder.serve_with_incoming_shutdown(incoming, async move {
                let _ = ready_tx.send(());
                shutdown_rx.await.ok();
                tracing::info!("{} gRPC server shutting down", server_name_str);
            });

            let server_name_str = server_name.to_string();

            tokio::spawn(async move {
                if let Err(e) = handle.await {
                    tracing::error!("{} gRPC server error: {:?}", server_name_str, e);
                }
            });
        }
    }

    // Wait for server to be ready
    let _ = ready_rx.await;
    tracing::info!("{} gRPC server started", server_name);

    Ok((addr, shutdown_tx))
}

pub async fn create_verifier_grpc_server<C: CitreaClientT>(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr, oneshot::Sender<()>), BridgeError> {
    let _rpc = ExtendedBitcoinRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
        None,
    )
    .await
    .wrap_err("Failed to connect to Bitcoin RPC")?;

    let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .wrap_err("Failed to parse address")?;
    let verifier = VerifierServer::<C>::new(config.clone()).await?;
    verifier.start_background_tasks().await?;

    let svc = ClementineVerifierServer::new(verifier)
        .max_encoding_message_size(config.grpc.max_message_size)
        .max_decoding_message_size(config.grpc.max_message_size);

    let (server_addr, shutdown_tx) =
        create_grpc_server(addr.into(), svc, "Verifier", &config).await?;

    match server_addr {
        ServerAddr::Tcp(socket_addr) => Ok((socket_addr, shutdown_tx)),
        _ => Err(BridgeError::ConfigError("Expected TCP address".into())),
    }
}

pub async fn create_operator_grpc_server<C: CitreaClientT>(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr, oneshot::Sender<()>), BridgeError> {
    tracing::info!(
        "config host and port are: {} and {}",
        config.host,
        config.port
    );
    let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .wrap_err("Failed to parse address")?;

    tracing::info!("Creating operator server");
    let operator = OperatorServer::<C>::new(config.clone()).await?;
    operator.start_background_tasks().await?;

    tracing::info!("Creating ClementineOperatorServer");
    let svc = ClementineOperatorServer::new(operator)
        .max_encoding_message_size(config.grpc.max_message_size)
        .max_decoding_message_size(config.grpc.max_message_size);
    let (server_addr, shutdown_tx) =
        create_grpc_server(addr.into(), svc, "Operator", &config).await?;
    tracing::info!("Operator gRPC server created");

    match server_addr {
        ServerAddr::Tcp(socket_addr) => Ok((socket_addr, shutdown_tx)),
        _ => Err(BridgeError::ConfigError("Expected TCP address".into())),
    }
}

pub async fn create_aggregator_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr, oneshot::Sender<()>), BridgeError> {
    let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .wrap_err("Failed to parse address")?;
    let aggregator_server = AggregatorServer::new(config.clone()).await?;
    aggregator_server.start_background_tasks().await?;

    let svc = ClementineAggregatorServer::new(aggregator_server)
        .max_encoding_message_size(config.grpc.max_message_size)
        .max_decoding_message_size(config.grpc.max_message_size);

    if config.client_verification {
        tracing::warn!("Client verification is enabled on aggregator gRPC server",);
    }

    let (server_addr, shutdown_tx) =
        create_grpc_server(addr.into(), svc, "Aggregator", &config).await?;

    match server_addr {
        ServerAddr::Tcp(socket_addr) => Ok((socket_addr, shutdown_tx)),
        _ => Err(BridgeError::ConfigError("Expected TCP address".into())),
    }
}

// Functions for creating servers with Unix sockets (useful for tests)
#[cfg(unix)]
pub async fn create_verifier_unix_server<C: CitreaClientT>(
    config: BridgeConfig,
    socket_path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, oneshot::Sender<()>), BridgeError> {
    let _rpc = ExtendedBitcoinRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
        None,
    )
    .await
    .wrap_err("Failed to connect to Bitcoin RPC")?;

    let verifier = VerifierServer::<C>::new(config.clone()).await?;
    verifier.start_background_tasks().await?;

    let svc = ClementineVerifierServer::new(verifier)
        .max_encoding_message_size(config.grpc.max_message_size)
        .max_decoding_message_size(config.grpc.max_message_size);

    let (server_addr, shutdown_tx) =
        create_grpc_server(socket_path.into(), svc, "Verifier", &config).await?;

    match server_addr {
        ServerAddr::Unix(path) => Ok((path, shutdown_tx)),
        _ => Err(BridgeError::ConfigError("Expected Unix socket path".into())),
    }
}

#[cfg(not(unix))]
pub async fn create_verifier_unix_server(
    _config: BridgeConfig,
    _socket_path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, oneshot::Sender<()>), BridgeError> {
    Err(BridgeError::ConfigError(
        "Unix sockets are not supported on this platform".into(),
    ))
}

#[cfg(unix)]
pub async fn create_operator_unix_server<C: CitreaClientT>(
    config: BridgeConfig,
    socket_path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, oneshot::Sender<()>), BridgeError> {
    let _rpc = ExtendedBitcoinRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
        None,
    )
    .await
    .wrap_err("Failed to connect to Bitcoin RPC")?;

    let operator = OperatorServer::<C>::new(config.clone()).await?;
    operator.start_background_tasks().await?;

    let svc = ClementineOperatorServer::new(operator)
        .max_encoding_message_size(config.grpc.max_message_size)
        .max_decoding_message_size(config.grpc.max_message_size);

    let (server_addr, shutdown_tx) =
        create_grpc_server(socket_path.into(), svc, "Operator", &config).await?;

    match server_addr {
        ServerAddr::Unix(path) => Ok((path, shutdown_tx)),
        _ => Err(BridgeError::ConfigError("Expected Unix socket path".into())),
    }
}

#[cfg(not(unix))]
pub async fn create_operator_unix_server(
    _config: BridgeConfig,
    _socket_path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, oneshot::Sender<()>), BridgeError> {
    Err(BridgeError::ConfigError(
        "Unix sockets are not supported on this platform".into(),
    ))
}

#[cfg(unix)]
pub async fn create_aggregator_unix_server(
    config: BridgeConfig,
    socket_path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, oneshot::Sender<()>), BridgeError> {
    let aggregator_server = AggregatorServer::new(config.clone()).await?;
    aggregator_server.start_background_tasks().await?;

    let svc = ClementineAggregatorServer::new(aggregator_server)
        .max_encoding_message_size(config.grpc.max_message_size)
        .max_decoding_message_size(config.grpc.max_message_size);

    let (server_addr, shutdown_tx) =
        create_grpc_server(socket_path.into(), svc, "Aggregator", &config).await?;

    match server_addr {
        ServerAddr::Unix(path) => Ok((path, shutdown_tx)),
        _ => Err(BridgeError::ConfigError("Expected Unix socket path".into())),
    }
}

#[cfg(not(unix))]
pub async fn create_aggregator_unix_server(
    _config: BridgeConfig,
    _socket_path: std::path::PathBuf,
) -> Result<(std::path::PathBuf, oneshot::Sender<()>), BridgeError> {
    Err(BridgeError::ConfigError(
        "Unix sockets are not supported on this platform".into(),
    ))
}
