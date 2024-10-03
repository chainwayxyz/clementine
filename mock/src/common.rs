//! # Common Test Utilities
//!
//! This file includes common functions/variables for tests.

use super::database::create_test_config_with_thread_name;
use clementine_core::servers::create_verifier_server;
use jsonrpsee::{http_client::HttpClient, server::ServerHandle};
use std::{env, net::TcpListener, path};

pub const ENV_CONF_FILE: &str = "TEST_CONFIG";

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
    let rpc = crate::create_extended_rpc!(config);
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

/// Returns configuration, read from configuration file which is specified from
/// either an environment variable or the function argument. Environment
/// variable is priotirized over the function argument `configuration_file`.
pub fn get_test_config(configuration_file: &str) -> Result<BridgeConfig, BridgeError> {
    let env_config: Option<BridgeConfig> = if let Ok(config_file_path) = env::var(ENV_CONF_FILE) {
        Some(BridgeConfig::try_parse_file(config_file_path.into())?)
    } else {
        None
    };

    // Read specified configuration file from `tests/data` directory.
    let mut config = match BridgeConfig::try_parse_file(
        format!(
            "{}/tests/data/{}",
            env!("CARGO_MANIFEST_DIR"),
            configuration_file
        )
        .into(),
    ) {
        Ok(c) => c,
        Err(e) => return Err(e),
    };

    // Overwrite user's environment to test's hard coded data if environment
    // file is specified.
    if let Some(env_config) = env_config {
        config.db_host = env_config.db_host;
        config.db_port = env_config.db_port;
        config.db_user = env_config.db_user;
        config.db_password = env_config.db_password;
        config.db_name = env_config.db_name;
    };

    #[cfg(test)]
    {
        config.port = 0;
    }

    Ok(config)
}

/// Finds consecutive idle ports starting from the given port, up to count num.
pub fn find_consecutive_idle_ports(port: u16, num: usize) -> Result<u16, BridgeError> {
    let mut idle_ports = Vec::new();
    let mut current_port = port;

    while current_port < 65535 {
        match TcpListener::bind(("0.0.0.0", current_port)) {
            Ok(_) => {
                idle_ports.push(current_port);
                current_port += 1;
                if idle_ports.len() == num + 1 {
                    break;
                }
                tracing::debug!(
                    "Ports {:?}-{:?} are available.",
                    current_port,
                    current_port + num as u16
                );
            }
            Err(_e) => {
                idle_ports.clear();
                if current_port < port + num as u16 {
                    tracing::debug!(
                        "Ports {:?}-{:?} are not available. Searching for new ports...",
                        current_port,
                        current_port + num as u16
                    );
                }
                current_port += 1;
            }
        }
    }

    if idle_ports.len() == num + 1 {
        Ok(idle_ports[0])
    } else {
        Err(BridgeError::PortError(
            "No consecutive idle ports found".to_string(),
        ))
    }
}

mod tests {
    #[tokio::test]
    async fn ports() {
        let res = super::find_consecutive_idle_ports(0, 5).unwrap();
        println!("{:?}", res);
    }
}
