//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::mock::common;
use crate::{
    config::BridgeConfig,
    create_test_config, create_test_config_with_thread_name,
    database::common::Database,
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
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError>
where
    R: RpcApiWrapper,
{
    let _ = Database::create_database(config.clone(), &config.db_name).await?;
    let database = Database::new(config.clone()).await.unwrap();
    database
        .run_sql_file("../scripts/schema.sql")
        .await
        .unwrap();
    database.close().await;
    // let config = create_test_config!(config.db_name, config);
    let server = match Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await
    {
        Ok(s) => s,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };
    let verifier = Verifier::new(rpc, config).await?;

    let addr: std::net::SocketAddr = match server.local_addr() {
        Ok(a) => a,
        Err(e) => return Err(BridgeError::ServerError(e)),
    };
    let handle = server.start(verifier.into_rpc());

    let client = HttpClientBuilder::default()
        .build(format!("http://{}:{}/", addr.ip(), addr.port()))
        .unwrap();

    tracing::info!("Verifier server started with address: {}", addr);

    Ok((client, handle, addr))
}

/// Starts the server for the operator.
pub async fn create_operator_server<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError>
where
    R: RpcApiWrapper,
{
    let _ = Database::create_database(config.clone(), &config.db_name).await?;
    let database = Database::new(config.clone()).await.unwrap();
    database
        .run_sql_file("../scripts/schema.sql")
        .await
        .unwrap();
    database.close().await;

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

    let client = HttpClientBuilder::default()
        .build(format!("http://{}:{}/", addr.ip(), addr.port()))
        .unwrap();

    tracing::info!("Operator server started with address: {}", addr);

    Ok((client, handle, addr))
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
pub async fn create_verifiers_and_operators<R>(
    config: BridgeConfig,
    rpc: ExtendedRpc<R>,
) -> (
    Vec<(HttpClient, ServerHandle, std::net::SocketAddr)>, // Verifier clients
    Vec<(HttpClient, ServerHandle, std::net::SocketAddr)>, // Operator clients
)
where
    R: RpcApiWrapper,
{
    let all_verifiers_secret_keys = config.all_verifiers_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the verifiers are required for testing");
    });
    let verifier_futures = all_verifiers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            create_verifier_server(
                BridgeConfig {
                    secret_key: *sk,
                    port: 0, // Use the index to calculate the port
                    db_name: config.db_name.clone() + &"verifier".to_string() + &i.to_string(),
                    db_user: config.db_user.clone() + &"verifier".to_string() + &i.to_string(),
                    ..config.clone()
                },
                rpc.clone(),
            )
        })
        .collect::<Vec<_>>();
    let verifier_endpoints = futures::future::try_join_all(verifier_futures)
        .await
        .unwrap();

    let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the operators are required for testing");
    });

    let operator_futures = all_operators_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            create_verifier_server(
                BridgeConfig {
                    secret_key: *sk,
                    port: 0, // Use the index to calculate the port
                    db_name: config.db_name.clone() + &"operator".to_string() + &i.to_string(),
                    db_user: config.db_user.clone() + &"operator".to_string() + &i.to_string(),
                    ..config.clone()
                },
                rpc.clone(),
            )
        })
        .collect::<Vec<_>>();
    let operator_endpoints = futures::future::try_join_all(operator_futures)
        .await
        .unwrap();

    (verifier_endpoints, operator_endpoints)
}
