//! # Servers
//!
//! Utilities for operator and verifier servers.
use crate::aggregator;
use crate::aggregator::Aggregator;
use crate::database::Database;
use crate::mock::database::create_test_config_with_thread_name;
use crate::rpc::clementine::clementine_aggregator_server::ClementineAggregatorServer;
use crate::rpc::clementine::clementine_operator_server::ClementineOperatorServer;
use crate::rpc::clementine::clementine_verifier_server::ClementineVerifierServer;
use crate::rpc::clementine::clementine_watchtower_server::ClementineWatchtowerServer;
use crate::traits::rpc::AggregatorServer;
use crate::watchtower::Watchtower;
use crate::{
    config::BridgeConfig,
    errors,
    extended_rpc::ExtendedRpc,
    operator,
    traits::{self, rpc::VerifierRpcServer},
    verifier::Verifier,
};
use errors::BridgeError;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::{Server, ServerHandle},
};
use operator::Operator;
use std::thread;
use traits::rpc::OperatorRpcServer;

pub type ServerFuture = dyn futures::Future<Output = Result<(), tonic::transport::Error>>;

/// Starts a server for a verifier.
#[tracing::instrument(skip(rpc), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
pub async fn create_verifier_server(
    config: BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError> {
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
pub async fn create_operator_server(
    config: BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<(HttpClient, ServerHandle, std::net::SocketAddr), BridgeError> {
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
    let config = create_test_config_with_thread_name(config_name, None).await;
    let start_port = config.port;
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url,
        config.bitcoin_rpc_user,
        config.bitcoin_rpc_password,
    )
    .await;
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

/// Starts operators, verifiers and aggergator gRPC servers. This function's intended use is for
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
// #[tracing::instrument(ret(level = tracing::Level::TRACE))]
#[allow(clippy::type_complexity)] // Enabling tracing::instrument causes this.
pub async fn create_actors_grpc(
    config: BridgeConfig,
    number_of_watchtowers: u32,
) -> (
    Vec<(std::net::SocketAddr,)>, // Verifier clients
    Vec<(std::net::SocketAddr,)>, // Operator clients
    (std::net::SocketAddr,),      // Aggregator client
    Vec<(std::net::SocketAddr,)>, // Watchtower clients
) {
    let start_port = config.port;
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;
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
            let mut config_with_new_db = config.clone();
            async move {
                config_with_new_db.db_name += &i;
                Database::initialize_database(&config_with_new_db)
                    .await
                    .unwrap();

                let verifier = create_verifier_grpc_server(
                    BridgeConfig {
                        secret_key: *sk,
                        port,
                        ..config_with_new_db.clone()
                    },
                    rpc,
                )
                .await?;
                Ok::<((std::net::SocketAddr,), BridgeConfig), BridgeError>((
                    verifier,
                    config_with_new_db,
                ))
            }
        })
        .collect::<Vec<_>>();
    let verifier_results = futures::future::try_join_all(verifier_futures)
        .await
        .unwrap();
    let verifier_endpoints = verifier_results.iter().map(|(v, _)| *v).collect::<Vec<_>>();
    let verifier_configs = verifier_results
        .iter()
        .map(|(_, c)| c.clone())
        .collect::<Vec<_>>();

    let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the operators are required for testing");
    });

    // Create futures for operator gRPC servers
    let operator_futures = all_operators_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let port = start_port + i as u16 + all_verifiers_secret_keys.len() as u16;
            let rpc = rpc.clone();
            let verifier_config = verifier_configs[i].clone();
            async move {
                let socket_addr = create_operator_grpc_server(
                    BridgeConfig {
                        secret_key: *sk,
                        port,
                        ..verifier_config
                    },
                    rpc,
                )
                .await?;
                Ok::<(std::net::SocketAddr,), BridgeError>(socket_addr)
            }
        })
        .collect::<Vec<_>>();

    let operator_endpoints = futures::future::try_join_all(operator_futures)
        .await
        .unwrap();

    // let config = create_test_config_with_thread_name(config_name, None).await;
    println!("Port: {}", start_port);
    let port = start_port
        + all_verifiers_secret_keys.len() as u16
        + all_operators_secret_keys.len() as u16
        + 1;
    // + all_operators_secret_keys.len() as u16;
    let aggregator = create_aggregator_grpc_server(BridgeConfig {
        port,
        verifier_endpoints: Some(
            verifier_endpoints
                .iter()
                .map(|(socket_addr,)| format!("http://{}", socket_addr))
                .collect(),
        ),
        operator_endpoints: Some(
            operator_endpoints
                .iter()
                .map(|(socket_addr,)| format!("http://{}", socket_addr))
                .collect(),
        ),
        ..verifier_configs[0].clone()
    })
    .await
    .unwrap();

    println!("Watchtower start port: {}", start_port);
    let port = start_port
        + all_verifiers_secret_keys.len() as u16
        + all_operators_secret_keys.len() as u16
        + 2;
    let wathctower_futures = (0..number_of_watchtowers)
        .map(|i| {
            let verifier_endpoints = verifier_endpoints.clone();
            let operator_endpoints = operator_endpoints.clone();
            let verifier_configs = verifier_configs.clone();

            create_watchtower_grpc_server(BridgeConfig {
                port: port + i as u16,
                verifier_endpoints: Some(
                    verifier_endpoints
                        .iter()
                        .map(|(socket_addr,)| format!("http://{}", socket_addr))
                        .collect(),
                ),
                operator_endpoints: Some(
                    operator_endpoints
                        .iter()
                        .map(|(socket_addr,)| format!("http://{}", socket_addr))
                        .collect(),
                ),
                ..verifier_configs[0].clone()
            })
        })
        .collect::<Vec<_>>();
    let wathctower_endpoints = futures::future::try_join_all(wathctower_futures)
        .await
        .unwrap();

    (
        verifier_endpoints,
        operator_endpoints,
        aggregator,
        wathctower_endpoints,
    )
}
