//! # Configuration Options
//!
//! This module defines configuration options.
//!
//! This module is base for `cli` module and not dependent on it. Therefore,
//! this module can be used independently.
//!
//! ## Configuration File
//!
//! Configuration options can be read from a TOML file. File contents are
//! described in `BridgeConfig` struct.

use crate::errors::BridgeError;
use bitcoin::Network;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{fs::File, io::Read, path::PathBuf};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Configuration options for any Clementine target (tests, binaries etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Tracing debug level.
    pub tracing_debug: String,
    /// Host of the operator or the verifier
    pub host: String,
    /// Port of the operator or the verifier
    pub port: u16,
    /// Bitcoin network to work on.
    pub network: Network,
    /// Secret key for the operator or the verifier.
    pub secret_key: SecretKey,
    /// Verifiers public keys, including operator's.
    pub verifiers_public_keys: Vec<PublicKey>,
    /// Number of verifiers.
    pub num_verifiers: usize,
    /// Minimum relay fee.
    pub min_relay_fee: u64,
    /// User takes after.
    pub user_takes_after: u32,
    /// Threshold for confirmation.
    pub confirmation_treshold: u32,
    /// Bitcoin remote procedure call URL.
    pub bitcoin_rpc_url: String,
    /// Bitcoin RPC user.
    pub bitcoin_rpc_user: String,
    /// Bitcoin RPC user password.
    pub bitcoin_rpc_password: String,
    /// All Secret keys. Just for testing purposes.
    pub all_secret_keys: Option<Vec<SecretKey>>,
    /// Verifier endpoints.
    pub verifier_endpoints: Option<Vec<String>>,
    /// PostgreSQL database host address.
    pub db_host: String,
    /// PostgreSQL database port.
    pub db_port: usize,
    /// PostgreSQL database user name.
    pub db_user: String,
    /// PostgreSQL database user password.
    pub db_password: String,
    /// PostgreSQL database name.
    pub db_name: String,
}

impl BridgeConfig {
    /// Create a new `BridgeConfig` with default values.
    pub fn new() -> Self {
        BridgeConfig {
            ..Default::default()
        }
    }

    /// Read contents of a TOML file and generate a `BridgeConfig`.
    pub fn try_parse_file(path: PathBuf) -> Result<Self, BridgeError> {
        let mut contents = String::new();

        let mut file = match File::open(path.clone()) {
            Ok(f) => f,
            Err(e) => return Err(BridgeError::ConfigError(e.to_string())),
        };
        if let Err(e) = file.read_to_string(&mut contents) {
            return Err(BridgeError::ConfigError(e.to_string()));
        }

        tracing::debug!("Using configuration file: {:?}", path);

        BridgeConfig::try_parse_from(contents)
    }

    /// Try to parse a `BridgeConfig` from given TOML formatted string and
    /// generate a `BridgeConfig`.
    pub fn try_parse_from(input: String) -> Result<Self, BridgeError> {
        let config = match toml::from_str::<BridgeConfig>(&input) {
            Ok(c) => Ok(c),
            Err(e) => Err(BridgeError::ConfigError(e.to_string())),
        }?;

        // Initialize tracing.
        if let Err(e) = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::from_str(&config.tracing_debug)
                    .unwrap_or_else(|_| EnvFilter::from_default_env()),
            )
            .try_init()
        {
            // If it failed because of a re-initialization, do not care about
            // the error.
            //
            // This error checking is kind of ugly. But nothing to do about it:
            // Library's error type is this.
            if e.to_string() != "a global default trace dispatcher has already been set" {
                return Err(BridgeError::ConfigError(e.to_string()));
            }
        };

        Ok(config)
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            tracing_debug: "debug".to_string(),
            host: "127.0.0.1".to_string(),
            port: 3030,
            secret_key: SecretKey::new(&mut secp256k1::rand::thread_rng()),
            verifiers_public_keys: vec![],
            num_verifiers: 4,
            min_relay_fee: 289,
            user_takes_after: 200,
            confirmation_treshold: 1,
            network: Network::Regtest,
            bitcoin_rpc_url: "http://127.0.0.1:18443".to_string(),
            bitcoin_rpc_user: "admin".to_string(),
            bitcoin_rpc_password: "admin".to_string(),
            all_secret_keys: None,
            verifier_endpoints: None,
            db_host: "127.0.0.1".to_string(),
            db_port: 5432,
            db_user: "postgres".to_string(),
            db_password: "postgres".to_string(),
            db_name: "postgres".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BridgeConfig;
    use std::{
        fs::{self, File},
        io::Write,
    };

    /// This needs a prefix for every test function, because of the async nature
    /// of the tests. I am not going to implement a mutex solution. Just do:
    /// let file_name = "someprefix".to_string() + TEST_FILE;
    pub const TEST_FILE: &str = "test.toml";

    #[test]
    fn parse_from_string() {
        // In case of a incorrect file content, we should receive an error.
        let content = "brokenfilecontent";
        match BridgeConfig::try_parse_from(content.to_string()) {
            Ok(_) => assert!(false),
            Err(e) => {
                println!("{:#?}", e);
                assert!(true);
            }
        };

        let init = BridgeConfig::new();
        match BridgeConfig::try_parse_from(toml::to_string(&init).unwrap()) {
            Ok(c) => {
                println!("{:#?}", c);
                assert!(true);
            }
            Err(_) => {
                assert!(false);
            }
        };
    }

    #[test]
    fn parse_from_file() {
        let file_name = "1".to_string() + TEST_FILE;
        let content = "brokenfilecontent";
        let mut file = File::create(file_name.clone()).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        match BridgeConfig::try_parse_file(file_name.clone().into()) {
            Ok(_) => {
                assert!(false);
            }
            Err(e) => {
                println!("{:#?}", e);
                assert!(true);
            }
        };

        // Read first example test file use for this test.
        let base_path = env!("CARGO_MANIFEST_DIR");
        let config_path = format!("{}/tests/data/test_config.toml", base_path);
        let content = fs::read_to_string(config_path).unwrap();
        let mut file = File::create(file_name.clone()).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        match BridgeConfig::try_parse_file(file_name.clone().into()) {
            Ok(c) => {
                println!("{:#?}", c);
                assert!(true);
            }
            Err(e) => {
                println!("{:#?}", e);
                assert!(false);
            }
        };

        fs::remove_file(file_name.clone()).unwrap();
    }

    #[test]
    /// Currently, no support for headers.
    fn parse_from_file_with_headers() {
        let file_name = "2".to_string() + TEST_FILE;
        let content = "[header1]
        num_verifiers = 4
        min_relay_fee = 289
        user_takes_after = 200

        [header2]
        confirmation_treshold = 1
        network = \"regtest\"
        bitcoin_rpc_url = \"http://localhost:18443\"
        bitcoin_rpc_user = \"admin\"
        bitcoin_rpc_password = \"admin\"\n";
        let mut file = File::create(file_name.clone()).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        match BridgeConfig::try_parse_file(file_name.clone().into()) {
            Ok(c) => {
                println!("{:#?}", c);
                assert!(false);
            }
            Err(e) => {
                println!("{:#?}", e);
                assert!(true);
            }
        };

        fs::remove_file(file_name).unwrap();
    }
}
