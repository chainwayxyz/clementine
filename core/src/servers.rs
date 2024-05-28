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
use bitcoincore_rpc::Auth;
use errors::BridgeError;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::{Server, ServerHandle},
};
use operator::Operator;
use traits::rpc::OperatorRpcServer;

/// Starts a server for a verifier.
pub async fn create_verifier_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );

    let server = Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await?;

    let verifier = Verifier::new(rpc, config).await?;

    let addr = server.local_addr()?;
    let handle = server.start(verifier.into_rpc());

    tracing::info!("Verifier server started with address: {}", addr);

    Ok((addr, handle))
}

/// Starts the server for the operator.
pub async fn create_operator_server(
    config: BridgeConfig,
    verifier_endpoints: Vec<String>,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );

    let verifiers: Vec<HttpClient> = verifier_endpoints
        .clone()
        .iter()
        .map(|verifier| HttpClientBuilder::default().build(verifier))
        .collect::<Result<Vec<HttpClient>, jsonrpsee::core::Error>>()?;

    let operator = Operator::new(config.clone(), rpc.clone(), verifiers).await?;

    let server = Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(operator.into_rpc());

    tracing::info!("Operator server started with address: {}", addr);

    Ok((addr, handle))
}

pub async fn start_operator_and_verifiers(
    config: BridgeConfig,
) -> (
    HttpClient,
    ServerHandle,
    Vec<(std::net::SocketAddr, ServerHandle)>,
) {
    let mut all_secret_keys = config.all_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys are required for testing");
    });
    all_secret_keys.pop().unwrap(); // Remove the operator secret key

    let futures = all_secret_keys
        .iter()
        .enumerate() // This adds the index to the iterator
        .map(|(i, sk)| {
            create_verifier_server(BridgeConfig {
                verifiers_public_keys: config.verifiers_public_keys.clone(),
                secret_key: *sk,
                port: 0, // Use the index to calculate the port
                db_name: config.db_name.clone() + &i.to_string(),
                ..config.clone()
            })
        })
        .collect::<Vec<_>>();

    // Use `futures::future::try_join_all` to run all futures concurrently and wait for all to complete
    let mut results = futures::future::try_join_all(futures).await.unwrap();
    let verifier_endpoints = results
        .iter()
        .map(|(socket_addr, _)| format!("http://{}:{}/", socket_addr.ip(), socket_addr.port()))
        .collect::<Vec<_>>();

    let (operator_socket_addr, operator_handle) =
        create_operator_server(config, verifier_endpoints)
            .await
            .unwrap();

    let operator_client = HttpClientBuilder::default()
        .build(&format!(
            "http://{}:{}/",
            operator_socket_addr.ip(),
            operator_socket_addr.port()
        ))
        .unwrap();
    results.push((operator_socket_addr, operator_handle.clone()));

    (operator_client, operator_handle, results)
}
