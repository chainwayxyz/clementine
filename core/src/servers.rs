//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::mock::database::create_test_config_with_thread_name;
use crate::traits::rpc::AggregatorServer;
use crate::{aggregator, create_extended_rpc};
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

#[tracing::instrument(ret(level = tracing::Level::TRACE))]
fn is_test_env() -> bool {
    // if thread name is not main then it is a test
    thread::current().name().unwrap_or_default() != "main"
}

/// Starts operators and verifiers servers. This function's intended use is for
/// tests.
///
/// # Returns
///
/// Returns a tuple of vectors of clients, handles, and addresses for the
/// verifiers + operators.
///
/// # Panics
///
/// Panics if there was an error while creating any of the servers.
#[tracing::instrument(ret(level = tracing::Level::TRACE))]
#[allow(clippy::type_complexity)] // Enabling tracing::instrument causes this.
pub async fn create_verifiers_and_operators(
    config_name: &str,
    // rpc: ExtendedRpc<R>,
) -> (
    Vec<(HttpClient, ServerHandle, std::net::SocketAddr)>, // Verifier clients
    Vec<(HttpClient, ServerHandle, std::net::SocketAddr)>, // Operator clients
    (HttpClient, ServerHandle, std::net::SocketAddr),      // Aggregator client
) {
    let mut config = create_test_config_with_thread_name(config_name, None).await;
    let start_port = config.port;
    let rpc = create_extended_rpc!(config);
    let all_verifiers_secret_keys = config.all_verifiers_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the verifiers are required for testing");
    });
    let verifier_futures = all_verifiers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let port = start_port + i as u16;
            // println!("Port: {}", port);
            let i = i.to_string();
            let rpc = rpc.clone();
            async move {
                let config_with_new_db =
                    create_test_config_with_thread_name(config_name, Some(&i.to_string())).await;
                let verifier = create_verifier_server(
                    BridgeConfig {
                        secret_key: *sk,
                        port: if is_test_env() { 0 } else { port },
                        ..config_with_new_db.clone()
                    },
                    rpc,
                )
                .await?;
                Ok::<
                    (
                        (HttpClient, ServerHandle, std::net::SocketAddr),
                        BridgeConfig,
                    ),
                    BridgeError,
                >((verifier, config_with_new_db))
            }
        })
        .collect::<Vec<_>>();
    let verifier_results = futures::future::try_join_all(verifier_futures)
        .await
        .unwrap();
    let verifier_endpoints = verifier_results
        .iter()
        .map(|(v, _)| v.clone())
        .collect::<Vec<_>>();
    let verifier_configs = verifier_results
        .iter()
        .map(|(_, c)| c.clone())
        .collect::<Vec<_>>();

    let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the operators are required for testing");
    });

    let operator_futures = all_operators_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let port = start_port + i as u16 + all_verifiers_secret_keys.len() as u16;
            let rpc = rpc.clone();
            let verifier_config = verifier_configs[i].clone();
            async move {
                create_operator_server(
                    BridgeConfig {
                        secret_key: *sk,
                        port: if is_test_env() { 0 } else { port },
                        ..verifier_config
                    },
                    rpc,
                )
                .await
            }
        })
        .collect::<Vec<_>>();
    let operator_endpoints = futures::future::try_join_all(operator_futures)
        .await
        .unwrap();

    let config = create_test_config_with_thread_name(config_name, None).await;
    println!("Port: {}", start_port);
    let port = start_port
        + all_verifiers_secret_keys.len() as u16
        + all_operators_secret_keys.len() as u16;
    let aggregator = create_aggregator_server(BridgeConfig {
        port: if is_test_env() { 0 } else { port },
        ..config
    })
    .await
    .unwrap();

    (verifier_endpoints, operator_endpoints, aggregator)
}
