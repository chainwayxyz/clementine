//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::aggregator;
use crate::traits::rpc::AggregatorServer;
use crate::{
    config::BridgeConfig,
    errors,
    extended_rpc::ExtendedRpc,
    operator,
    traits::{self, rpc::VerifierRpcServer},
    verifier::Verifier,
};
use bitcoin_mock_rpc::RpcApiWrapper;
use errors::BridgeError;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::{Server, ServerHandle},
};
use operator::Operator;
use std::thread;
use traits::rpc::OperatorRpcServer;

/// Starts a server for a verifier.
#[tracing::instrument(skip(rpc), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub async fn create_verifier_server<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError>
where
    R: RpcApiWrapper,
{
    let server = match Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await
    {
        Ok(s) => s,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };
    let verifier = Verifier::new(rpc, config).await?;

    let addr: std::net::SocketAddr = server.local_addr().map_err(BridgeError::ServerError)?;
    let handle = server.start(verifier.into_rpc());

    let client =
        HttpClientBuilder::default().build(format!("http://{}:{}/", addr.ip(), addr.port()))?;

    tracing::info!("Verifier server started with address: {}", addr);

    Ok((client, handle, addr))
}

/// Starts the server for the operator.
#[tracing::instrument(skip(rpc), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub async fn create_operator_server<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError>
where
    R: RpcApiWrapper,
{
    let operator = Operator::new(config.clone(), rpc).await?;

    let server = match Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await
    {
        Ok(s) => s,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };

    let addr: std::net::SocketAddr = server.local_addr().map_err(BridgeError::ServerError)?;
    let handle = server.start(operator.into_rpc());

    let client =
        HttpClientBuilder::default().build(format!("http://{}:{}/", addr.ip(), addr.port()))?;

    tracing::info!("Operator server started with address: {}", addr);

    Ok((client, handle, addr))
}

/// Starts the server for the aggregator.
#[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub async fn create_aggregator_server(
    config: BridgeConfig,
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError> {
    let aggregator = aggregator::Aggregator::new(config.clone()).await?;

    let server = match Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await
    {
        Ok(s) => s,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };

    let addr: std::net::SocketAddr = server.local_addr().map_err(BridgeError::ServerError)?;
    let handle = server.start(aggregator.into_rpc());

    let client =
        HttpClientBuilder::default().build(format!("http://{}:{}/", addr.ip(), addr.port()))?;

    tracing::info!("Aggregator server started with address: {}", addr);

    Ok((client, handle, addr))
}
