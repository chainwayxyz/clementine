use std::env;

use bitcoin::Network;
use bitcoincore_rpc::Auth;

use crate::errors::BridgeError;

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub db_file_path: String,
    pub num_verifiers: usize,
    pub min_relay_fee: u64,
    pub user_takes_after: u32,
    pub confirmation_treshold: u32,
    pub network: Network,
    pub bitcoin_rpc_url: String,
    pub bitcoin_rpc_auth: Auth,
    pub operator_ip: String,
    pub operator_port: u16,
    pub verifier_ip: String,
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
        let confirmation_treshold = env::var("CONFIRMATION_THRESHOLD")
            .map_err(|_| {
                BridgeError::ConfigError(
                    "CONFIRMATION_THRESHOLD environment variable not set".to_string(),
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

        let bitcoin_rpc_url = env::var("BITCOIN_RPC_URL").map_err(|_| {
            BridgeError::ConfigError("BITCOIN_RPC_URL environment variable not set".to_string())
        })?;
        let bitcoin_rpc_user = env::var("BITCOIN_RPC_USER").map_err(|_| {
            BridgeError::ConfigError("BITCOIN_RPC_USER environment variable not set".to_string())
        })?;

        let bitcoin_rpc_password = env::var("BITCOIN_RPC_PASSWORD").map_err(|_| {
            BridgeError::ConfigError(
                "BITCOIN_RPC_PASSWORD environment variable not set".to_string(),
            )
        })?;
        let bitcoin_rpc_auth = Auth::UserPass(bitcoin_rpc_user, bitcoin_rpc_password);

        let operator_ip = env::var("OPERATOR_IP").map_err(|_| {
            BridgeError::ConfigError("OPERATOR_IP environment variable not set".to_string())
        })?;

        let operator_port = env::var("OPERATOR_PORT")
            .map_err(|_| {
                BridgeError::ConfigError("OPERATOR_PORT environment variable not set".to_string())
            })?
            .parse::<u16>()
            .unwrap();

        let verifier_ip = env::var("VERIFIER_IP").map_err(|_| {
            BridgeError::ConfigError("VERIFIER_IP environment variable not set".to_string())
        })?;

        Ok(Self {
            db_file_path,
            num_verifiers,
            min_relay_fee,
            user_takes_after,
            confirmation_treshold,
            network,
            bitcoin_rpc_url,
            bitcoin_rpc_auth,
            operator_ip,
            operator_port,
            verifier_ip,
        })
    }

    pub fn test_config() -> Self {
        Self {
            db_file_path: "test_db".to_string(),
            num_verifiers: 4,
            min_relay_fee: 289,
            user_takes_after: 200,
            confirmation_treshold: 1,
            network: Network::Regtest,
            bitcoin_rpc_url: "http://localhost:18443".to_string(),
            bitcoin_rpc_auth: Auth::UserPass("admin".to_string(), "admin".to_string()),
            operator_ip: "127.0.0.1".to_string(),
            operator_port: 3030,
            verifier_ip: "127.0.0.1".to_string(),
        }
    }
}
