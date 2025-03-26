//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::aggregator::Aggregator;
use crate::citrea::CitreaClientT;
use crate::extended_rpc::ExtendedRpc;
use crate::operator::OperatorServer;
use crate::rpc::clementine::clementine_aggregator_server::ClementineAggregatorServer;
use crate::rpc::clementine::clementine_operator_server::ClementineOperatorServer;
use crate::rpc::clementine::clementine_verifier_server::ClementineVerifierServer;
use crate::verifier::VerifierServer;
use crate::{config::BridgeConfig, errors};
use errors::BridgeError;
use eyre::Context;
use std::thread;
use tokio::sync::oneshot;
use tonic::server::NamedService;

pub type ServerFuture = dyn futures::Future<Output = Result<(), tonic::transport::Error>>;

#[tracing::instrument(ret(level = tracing::Level::TRACE))]
fn is_test_env() -> bool {
    // if thread name is not main then it is a test
    thread::current().name().unwrap_or_default() != "main"
}

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

    let server_builder = tonic::transport::Server::builder().add_service(service);

    match addr {
        ServerAddr::Tcp(socket_addr) => {
            tracing::info!(
                "Starting {} gRPC server with TCP address: {}",
                server_name,
                socket_addr
            );
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
    let _rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .wrap_err("Failed to connect to Bitcoin RPC")?;

    let addr: std::net::SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .wrap_err("Failed to parse address")?;
    let verifier = VerifierServer::<C>::new(config).await?;
    let svc = ClementineVerifierServer::new(verifier);

    let (server_addr, shutdown_tx) = create_grpc_server(addr.into(), svc, "Verifier").await?;

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
    let operator = OperatorServer::<C>::new(config).await?;
    tracing::info!("Operator gRPC server created");
    let svc = ClementineOperatorServer::new(operator);

    let (server_addr, shutdown_tx) = create_grpc_server(addr.into(), svc, "Operator").await?;

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
    let aggregator = Aggregator::new(config).await?;
    let svc = ClementineAggregatorServer::new(aggregator);

    let (server_addr, shutdown_tx) = create_grpc_server(addr.into(), svc, "Aggregator").await?;

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
    let _rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .wrap_err("Failed to connect to Bitcoin RPC")?;

    let verifier = VerifierServer::<C>::new(config).await?;
    let svc = ClementineVerifierServer::new(verifier);

    let (server_addr, shutdown_tx) =
        create_grpc_server(socket_path.into(), svc, "Verifier").await?;

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
    let _rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .wrap_err("Failed to connect to Bitcoin RPC")?;

    let operator = OperatorServer::<C>::new(config).await?;
    let svc = ClementineOperatorServer::new(operator);

    let (server_addr, shutdown_tx) =
        create_grpc_server(socket_path.into(), svc, "Operator").await?;

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
    let aggregator = Aggregator::new(config).await?;
    let svc = ClementineAggregatorServer::new(aggregator);

    let (server_addr, shutdown_tx) =
        create_grpc_server(socket_path.into(), svc, "Aggregator").await?;

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
