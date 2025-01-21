use bitcoin::{Amount, BlockHash};
use crypto_bigint::U256;

/// For connector tree utxos, we should wait some time for any verifier to burn the branch if preimage is revealed
pub const CONNECTOR_TREE_OPERATOR_TAKES_AFTER: u16 = 1;

/// Dust value for mempool acceptance
pub const DUST_VALUE: Amount = Amount::from_sat(1000);

/// This is temporary. to be able to set PERIOD_END_BLOCK_HEIGHTS
pub const PERIOD_BLOCK_COUNT: u32 = 50; // 10 mins for 1 block, 6 months = 6*30*24*6 = 25920

/// K_DEEP is the give time to verifier to make a proper challenge
pub const K_DEEP: u32 = 3;

/// MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS is maximum number of blocks a single bitvm challenge response can take
pub const MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS: u32 = 5;

pub type VerifierChallenge = (BlockHash, U256, u8);
