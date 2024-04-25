use std::env;

use crate::errors::BridgeError;

pub struct BridgeConfig {
    pub num_verifiers: usize,
    pub num_users: usize,
    pub connector_tree_operator_takes_after: u16,
    pub connector_tree_depth: usize,
    pub dust_value: u64,
    pub min_relay_fee: u64,
    pub period_block_count: u32,
    pub user_takes_after: u32,
    pub confirmation_block_count: u32,
    pub k_deep: u32,
    pub max_bitvm_challenge_response_blocks: u32,
    pub test_mode: bool,
    pub db_file_path: String,
}

impl BridgeConfig {
    pub fn new() -> Result<Self, BridgeError> {
        // read from env, if it does not exist, raise an error
        let db_file_path = env::var("DB_FILE_PATH").map_err(|_| {
            BridgeError::ConfigError("DB_FILE_PATH environment variable not set".to_string())
        })?;
        
        Ok(Self {
            num_verifiers: 4,
            num_users: 4,
            connector_tree_operator_takes_after: 1,
            connector_tree_depth: 32,
            dust_value: 1000,
            min_relay_fee: 289,
            period_block_count: 50,
            user_takes_after: 200,
            confirmation_block_count: 1,
            k_deep: 3,
            max_bitvm_challenge_response_blocks: 5,
            test_mode: true,
            db_file_path,
        })
    }
}
