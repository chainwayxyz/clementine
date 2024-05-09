//! # Common Test Utilities
//!
//! This file includes common functions/variables for tests.
//!
//! Why is this file is here? If it is in `tests` subdirectory, unit tests can't
//! reach them.

use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use std::{env, net::TcpListener};

pub const ENV_CONF_FILE: &str = "TEST_CONFIG";

/// Returns test path for the specified test configuration.
pub fn get_test_config(configuration_file: &str) -> Result<BridgeConfig, BridgeError> {
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

    // let port = find_consecutive_idle_ports(config.port, config.num_verifiers).unwrap()
    config.port = 0;

    Ok(config)
}

/// Reads configuration file specified with `ENV_CONF_FILE` environment variable
/// and parses in to a `BridgeConfig`. If environment variable is not satisfied,
/// `fallback_config` will be used.
pub fn get_test_config_from_environment(
    fallback_config: &str,
) -> Result<BridgeConfig, BridgeError> {
    if let Ok(config_file_path) = env::var(ENV_CONF_FILE) {
        BridgeConfig::try_parse_file(config_file_path.into())
    } else {
        get_test_config(&fallback_config)
    }
}

/// Retrieves the list of configuration files in `tests/data` directory.
///
/// WIP
pub fn _get_all_test_configs() -> Result<Vec<BridgeConfig>, BridgeError> {
    todo!()
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
