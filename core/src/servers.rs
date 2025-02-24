//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::aggregator::Aggregator;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::clementine_aggregator_server::ClementineAggregatorServer;
use crate::rpc::clementine::clementine_operator_server::ClementineOperatorServer;
use crate::rpc::clementine::clementine_verifier_server::ClementineVerifierServer;
use crate::rpc::clementine::clementine_watchtower_server::ClementineWatchtowerServer;
use crate::watchtower::Watchtower;
use crate::{config::BridgeConfig, errors, operator, verifier::Verifier};
use errors::BridgeError;
use operator::Operator;
use std::thread;
use tokio::sync::oneshot;

pub type ServerFuture = dyn futures::Future<Output = Result<(), tonic::transport::Error>>;

#[tracing::instrument(ret(level = tracing::Level::TRACE))]
fn is_test_env() -> bool {
    // if thread name is not main then it is a test
    thread::current().name().unwrap_or_default() != "main"
}

pub async fn create_verifier_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    let _rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await?;

    let addr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!("Starting verifier gRPC server with address: {}", addr);
    let verifier = Verifier::new(config).await?;
    let svc = ClementineVerifierServer::new(verifier);

    // Create a channel to signal when the server is ready
    let (tx, rx) = oneshot::channel();

    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, async {
            // Signal that the server is bound and ready
            let _ = tx.send(());
            // Wait for shutdown signal (optional - you can add shutdown handling here)
            std::future::pending::<()>().await;
        });

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
        }
    });

    // Wait for server to be ready
    let _ = rx.await;

    tracing::info!("Verifier gRPC server started with address: {}", addr);
    Ok((addr,))
}

pub async fn create_operator_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    let _rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await?;

    tracing::info!(
        "config host and port are: {} and {}",
        config.host,
        config.port
    );
    let addr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!("Starting operator gRPC server with address: {}", addr);
    let operator = Operator::new(config).await?;
    tracing::info!("Operator gRPC server created");
    let svc = ClementineOperatorServer::new(operator);

    let (tx, rx) = oneshot::channel();

    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, async {
            let _ = tx.send(());
            std::future::pending::<()>().await;
        });

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
        }
    });

    let _ = rx.await;

    tracing::info!("operator gRPC server started with address: {}", addr);
    Ok((addr,))
}

pub async fn create_aggregator_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    let addr = format!("{}:{}", config.host, config.port).parse()?;
    let aggregator = Aggregator::new(config).await?;
    let svc = ClementineAggregatorServer::new(aggregator);

    let (tx, rx) = oneshot::channel();

    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, async {
            let _ = tx.send(());
            std::future::pending::<()>().await;
        });

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
        }
    });

    let _ = rx.await;

    tracing::info!("Aggregator gRPC server started with address: {}", addr);
    Ok((addr,))
}

pub async fn create_watchtower_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    let addr = format!("{}:{}", config.host, config.port).parse()?;
    let watchtower = Watchtower::new(config).await?;
    let svc = ClementineWatchtowerServer::new(watchtower);

    let (tx, rx) = oneshot::channel();

    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve_with_shutdown(addr, async {
            let _ = tx.send(());
            std::future::pending::<()>().await;
        });

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
        }
    });

    let _ = rx.await;

    tracing::info!("Watchtower gRPC server started with address: {}", addr);
    Ok((addr,))
}
