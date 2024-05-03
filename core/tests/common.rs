//! # Common Test Utilities
//!
//! This file includes common functions/variables for tests.

use std::net::TcpListener;

use clementine_core::{config::BridgeConfig, create_operator_server, create_verifier_server};
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerHandle,
};

/// Returns test path for the specified test configuration.
pub fn get_test_config(configuration_file: &str) -> String {
    format!(
        "{}/tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        configuration_file
    )
}

/// Retrieves the list of configuration files in `tests/data` directory.
///
/// Currently WIP
pub fn _get_all_test_configs() -> Vec<String> {
    todo!()
}

/// Finds consecutive idle ports starting from the given port, up to count num.
pub fn find_consecutive_idle_ports(port: u16, num: usize) -> Result<Vec<u16>, String> {
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
            }
            Err(e) => {
                idle_ports.clear();
                current_port += 1;
                tracing::debug!("Port {:?} is in use: {:?}", current_port, e);
            }
        }
    }
    if idle_ports.len() == num + 1 {
        Ok(idle_ports)
    } else {
        Err("No consecutive idle ports found".to_string())
    }
}
