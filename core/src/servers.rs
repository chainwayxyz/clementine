//! # Servers
//!
//! Utilities for operator and verifier servers.

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
use traits::rpc::OperatorRpcServer;

/// Starts a server for a verifier.
pub async fn create_verifier_server<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError>
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

    let addr = match server.local_addr() {
        Ok(a) => a,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };
    let handle = server.start(verifier.into_rpc());

    tracing::info!("Verifier server started with address: {}", addr);

    Ok((addr, handle))
}

/// Starts the server for the operator.
pub async fn create_operator_server<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
    verifier_endpoints: Vec<String>,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError>
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

    let addr = match server.local_addr() {
        Ok(s) => s,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };
    let handle = server.start(operator.into_rpc());

    tracing::info!("Operator server started with address: {}", addr);

    Ok((addr, handle))
}

/// Starts operator and verifiers servers. This function's intended use is for
/// tests.
///
/// # Returns
///
/// Returns a tuple, containing `HttpClient` for operator, `ServerHandle` for
/// operator and a vector containing `SocketAddr` and `ServerHandle` for
/// verifiers + operator (operator last).
///
/// # Panics
///
/// Panics if there was an error while creating any of the servers.
pub async fn create_operator_and_verifiers<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
) -> (
    HttpClient,
    ServerHandle,
    Vec<(std::net::SocketAddr, ServerHandle)>,
)
where
    R: RpcApiWrapper,
{
    let mut all_secret_keys = config.all_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys are required for testing");
    });
    // Remove the operator secret key.
    all_secret_keys.pop().unwrap();

    let futures = all_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            create_verifier_server(
                BridgeConfig {
                    verifiers_public_keys: config.verifiers_public_keys.clone(),
                    secret_key: *sk,
                    port: 0, // Use the index to calculate the port
                    db_name: config.db_name.clone() + &i.to_string(),
                    ..config.clone()
                },
                rpc.clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut results = futures::future::try_join_all(futures).await.unwrap();

    let verifier_endpoints: Vec<String> = results
        .iter()
        .map(|(socket_addr, _)| format!("http://{}:{}/", socket_addr.ip(), socket_addr.port()))
        .collect();

    let (operator_socket_addr, operator_handle) =
        create_operator_server(config, rpc, verifier_endpoints)
            .await
            .unwrap();
    let operator_client = HttpClientBuilder::default()
        .build(format!(
            "http://{}:{}/",
            operator_socket_addr.ip(),
            operator_socket_addr.port()
        ))
        .unwrap();
    results.push((operator_socket_addr, operator_handle.clone()));

    (operator_client, operator_handle, results)
}
