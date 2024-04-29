//! # Configuration Options
//!
//! This module defines configuration options. This information can be passed to
//! other parts of the program.
//!
//! ## Configuration File
//!
//! Configuration options can be read from a TOML file.

use crate::errors::BridgeError;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Error, Read},
    path::PathBuf,
};

/// This struct can be used to pass information to other parts of the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// File path for the mock database.
    pub db_file_path: String,
    /// Number of verifiers.
    pub num_verifiers: usize,
    /// Minimum relay fee.
    pub min_relay_fee: u64,
    /// User takes after.
    pub user_takes_after: u32,
    /// Threshold for confirmation.
    pub confirmation_treshold: u32,
    /// Bitcoin network to work on.
    pub network: Network,
    /// Bitcoin remote procedure call URL.
    pub bitcoin_rpc_url: String,
    /// Bitcoin RPC user.
    pub bitcoin_rpc_user: String,
    /// Bitcoin RPC user password.
    pub bitcoin_rpc_password: String,
}

impl BridgeConfig {
    pub fn new() -> Self {
        BridgeConfig {
            ..Default::default()
        }
    }

    /// Read contents of a TOML file and generate a `BridgeConfig`.
    pub fn try_parse_file(path: PathBuf) -> Result<Self, BridgeError> {
        let mut contents = String::new();

        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => return Err(BridgeError::ConfigError(e.to_string())),
        };
        if let Err(e) = file.read_to_string(&mut contents) {
            return Err(BridgeError::ConfigError(e.to_string()));
        }

        tracing::debug!("Configuration file size: {} bytes", contents.len());
        tracing::debug!("Configuration file contents: {}", &contents);

        BridgeConfig::try_parse_from(contents)
    }

    /// Try to parse a `BridgeConfig` from given TOML formatted string and
    /// generate a `BridgeConfig`.
    pub fn try_parse_from(input: String) -> Result<Self, BridgeError> {
        if let Ok(result) = toml::from_str::<BridgeConfig>(&input) {
            return Ok(result);
        };

        Err(BridgeError::ConfigError(Error::last_os_error().to_string()))
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            db_file_path: "database".to_string(),
            num_verifiers: 4,
            min_relay_fee: 289,
            user_takes_after: 200,
            confirmation_treshold: 1,
            network: Network::Regtest,
            bitcoin_rpc_url: "http://localhost:18443".to_string(),
            bitcoin_rpc_user: "admin".to_string(),
            bitcoin_rpc_password: "admin".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {}
