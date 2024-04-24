use std::env;

use bitcoin::{BlockHash, Network};
use clementine_circuits::constants::CLAIM_MERKLE_TREE_DEPTH;
use crypto_bigint::U256;
use lazy_static::lazy_static;

pub const NUM_VERIFIERS: usize = 4;
pub const NUM_USERS: usize = 4;

/// For connector tree utxos, we should wait some time for any verifier to burn the branch if preimage is revealed
pub const CONNECTOR_TREE_OPERATOR_TAKES_AFTER: u16 = 1;

/// Depth of the utxo tree from the source connector utxo, it is probably equal to claim merkle tree depth
pub const CONNECTOR_TREE_DEPTH: usize = CLAIM_MERKLE_TREE_DEPTH;

/// Dust value for mempool acceptance
pub const DUST_VALUE: u64 = 1000;
/// Minimum relay fee for mempool acceptance
pub const MIN_RELAY_FEE: u64 = 289;

/// This is temporary. to be able to set PERIOD_END_BLOCK_HEIGHTS
pub const PERIOD_BLOCK_COUNT: u32 = 50; // 10 mins for 1 block, 6 months = 6*30*24*6 = 25920

/// For deposits, every user makes a timelock to take the money back if deposit deos not happen,
/// one reason is to not spam the bridge operator
pub const USER_TAKES_AFTER: u32 = 200;

/// For deposits, bridge operator does not accept the tx if it is not confirmed
pub const CONFIRMATION_BLOCK_COUNT: u32 = 1;

/// K_DEEP is the give time to verifier to make a proper challenge
pub const K_DEEP: u32 = 3;

/// MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS is maximum number of blocks a single bitvm challenge response can take
pub const MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS: u32 = 5;

pub type VerifierChallenge = (BlockHash, U256, u8);

lazy_static! {
    /// This will act as a constant during runtime once it is initialized
    pub static ref NETWORK: Network = {
        // Retrieve the network type from an environment variable
        let network_str = env::var("NETWORK").unwrap_or("Regtest".to_string());

        // Convert the environment variable to a `bitcoin::Network`
        match network_str.to_lowercase().as_str() {
            "bitcoin" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => panic!("Unsupported network: {}", network_str),
        }
    };
}

pub const TEST_MODE: bool = true;
pub const TEXT_DATABASE: &str = "database";
