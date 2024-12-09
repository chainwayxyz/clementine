//! # Common Test Utilities
//!
//! This file includes common functions/variables for tests.

use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use std::{env, net::TcpListener};

pub const ENV_CONF_FILE: &str = "TEST_CONFIG";

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
