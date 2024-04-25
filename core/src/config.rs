use std::env;

use bitcoin::Network;

use crate::errors::BridgeError;

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub db_file_path: String,
    pub num_verifiers: usize,
    pub min_relay_fee: u64,
    pub user_takes_after: u32,
    pub confirmation_block_count: u32,
    pub network: Network,
}

impl BridgeConfig {
    pub fn new() -> Result<Self, BridgeError> {
        // read from env, if it does not exist, raise an error
        let db_file_path = env::var("DB_FILE_PATH").map_err(|_| {
            BridgeError::ConfigError("DB_FILE_PATH environment variable not set".to_string())
        })?;
        let num_verifiers = env::var("NUM_VERIFIERS")
            .map_err(|_| {
                BridgeError::ConfigError("NUM_VERIFIERS environment variable not set".to_string())
            })?
            .parse::<usize>()
            .unwrap();
        let min_relay_fee = env::var("MIN_RELAY_FEE")
            .map_err(|_| {
                BridgeError::ConfigError("MIN_RELAY_FEE environment variable not set".to_string())
            })?
            .parse::<u64>()
            .unwrap();
        let user_takes_after = env::var("USER_TAKES_AFTER")
            .map_err(|_| {
                BridgeError::ConfigError(
                    "USER_TAKES_AFTER environment variable not set".to_string(),
                )
            })?
            .parse::<u32>()
            .unwrap();
        let confirmation_block_count = env::var("CONFIRMATION_BLOCK_COUNT")
            .map_err(|_| {
                BridgeError::ConfigError(
                    "CONFIRMATION_BLOCK_COUNT environment variable not set".to_string(),
                )
            })?
            .parse::<u32>()
            .unwrap();

        let network_str = env::var("NETWORK").unwrap_or("Regtest".to_string());

        // Convert the environment variable to a `bitcoin::Network`
        let network = match network_str.to_lowercase().as_str() {
            "bitcoin" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => panic!("Unsupported network: {}", network_str),
        };

        Ok(Self {
            db_file_path,
            num_verifiers,
            min_relay_fee,
            user_takes_after,
            confirmation_block_count,
            network,
        })
    }

    pub fn test_config() -> Self {
        Self {
            db_file_path: "test_db".to_string(),
            num_verifiers: 4,
            min_relay_fee: 289,
            user_takes_after: 200,
            confirmation_block_count: 1,
            network: Network::Regtest,
        }
    }
}
