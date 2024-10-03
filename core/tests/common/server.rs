use std::thread;

use crate::{common::database::create_test_config_with_thread_name, create_extended_rpc};
use clementine_core::{
    config::BridgeConfig,
    errors::BridgeError,
    servers::{create_aggregator_server, create_operator_server, create_verifier_server},
};
use jsonrpsee::{http_client::HttpClient, server::ServerHandle};

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

fn is_test_env() -> bool {
    // if thread name is not main then it is a test
    thread::current().name().unwrap_or_default() != "main"
}
