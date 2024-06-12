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
    if let Ok(config_file_path) = env::var(ENV_CONF_FILE) {
        return BridgeConfig::try_parse_file(config_file_path.into());
    }

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

/// Creates a temporary database for testing.
///
/// Parameters:
///
/// - db_name: New database's name.
/// - config_file: Test configuration file. Rest of the config will be read from
/// here and only `db_name` will be overwritten.
///
/// Returns new `BridgeConfig`.
#[macro_export]
macro_rules! create_test_database {
    ($db_name:expr, $config_file:expr) => {{
        let config = common::get_test_config($config_file).unwrap();
        let config = Database::create_database(config, &$db_name).await.unwrap();

        let database = Database::new(config.clone()).await.unwrap();
        database
            .run_sql_file("../scripts/schema.sql")
            .await
            .unwrap();

        database.close().await;

        config
    }};
}

/// Creates a temporary database for testing, using current thread's name as the
/// database name.
///
/// Parameters:
///
/// - config_file: Test configuration file. Rest of the config will be read from
/// here and only `db_name` will be overwritten.
///
/// Returns new `BridgeConfig`.
#[macro_export]
macro_rules! create_test_database_with_thread_name {
    ($config_file:expr) => {{
        let handle = thread::current()
            .name()
            .unwrap()
            .split(":")
            .last()
            .unwrap()
            .to_owned();

        create_test_database!(handle, $config_file)
    }};
}
