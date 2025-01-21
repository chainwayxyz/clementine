use bitcoin::BlockHash;
// use clementine_circuits::constants::CLAIM_MERKLE_TREE_DEPTH;
use crypto_bigint::U256;

// /// For deposits, bridge operator does not accept the tx if it is not confirmed
// pub const CONFIRMATION_BLOCK_COUNT: u32 = 1;

/// K_DEEP is the give time to verifier to make a proper challenge
pub const K_DEEP: u32 = 3;

/// MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS is maximum number of blocks a single bitvm challenge response can take
pub const MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS: u32 = 5;

pub type VerifierChallenge = (BlockHash, U256, u8);

// pub const TEST_MODE: bool = true;

// dummy number of BitVM disprove scripts
pub const NUM_INTERMEDIATE_STEPS: usize = 100;

pub const PARALLEL_ASSERT_TX_CHAIN_SIZE: usize = 10;
