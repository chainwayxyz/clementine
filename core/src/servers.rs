//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::aggregator::Aggregator;
use crate::rpc::clementine::clementine_aggregator_server::ClementineAggregatorServer;
use crate::rpc::clementine::clementine_operator_server::ClementineOperatorServer;
use crate::rpc::clementine::clementine_verifier_server::ClementineVerifierServer;
use crate::rpc::clementine::clementine_watchtower_server::ClementineWatchtowerServer;
use crate::watchtower::Watchtower;
use crate::{
    config::BridgeConfig, errors, extended_rpc::ExtendedRpc, operator, verifier::Verifier,
};
use errors::BridgeError;
use operator::Operator;
use std::thread;

pub type ServerFuture = dyn futures::Future<Output = Result<(), tonic::transport::Error>>;

#[tracing::instrument(ret(level = tracing::Level::TRACE))]
fn is_test_env() -> bool {
    // if thread name is not main then it is a test
    thread::current().name().unwrap_or_default() != "main"
}

pub async fn create_verifier_grpc_server(
    config: BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    tracing::info!(
        "config host and port are: {} and {}",
        config.host,
        config.port
    );
    let addr = format!("{}:{}", config.host, config.port).parse().unwrap();
    tracing::info!("Starting verifier gRPC server with address: {}", addr);
    let verifier = Verifier::new(rpc, config).await?;
    tracing::info!("Verifier gRPC server created");
    let svc = ClementineVerifierServer::new(verifier);
    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve(addr);

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
        }
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    tracing::info!("Verifier gRPC server started with address: {}", addr);
    Ok((addr,))
}

pub async fn create_operator_grpc_server(
    config: BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    tracing::info!(
        "config host and port are: {} and {}",
        config.host,
        config.port
    );
    let addr = format!("{}:{}", config.host, config.port).parse().unwrap();
    tracing::info!("Starting operator gRPC server with address: {}", addr);
    let operator = Operator::new(config, rpc).await?;
    tracing::info!("Operator gRPC server created");
    let svc = ClementineOperatorServer::new(operator);
    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve(addr);

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
        }
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    tracing::info!("operator gRPC server started with address: {}", addr);
    Ok((addr,))
}

pub async fn create_aggregator_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    let addr = format!("{}:{}", config.host, config.port).parse().unwrap();
    let aggregator = Aggregator::new(config).await?;
    let svc = ClementineAggregatorServer::new(aggregator);
    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve(addr);

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
            panic!("gRPC server error: {:?}", e);
        }
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    tracing::info!("Aggregator gRPC server started with address: {}", addr);
    Ok((addr,))
}

pub async fn create_watchtower_grpc_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr,), BridgeError> {
    let addr = format!("{}:{}", config.host, config.port).parse().unwrap();
    let watchtower = Watchtower::new(config).await?;
    let svc = ClementineWatchtowerServer::new(watchtower);
    let handle = tonic::transport::Server::builder()
        .add_service(svc)
        .serve(addr);

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("gRPC server error: {:?}", e);
            panic!("gRPC server error: {:?}", e);
        }
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    tracing::info!("Watchtower gRPC server started with address: {}", addr);
    Ok((addr,))
}
