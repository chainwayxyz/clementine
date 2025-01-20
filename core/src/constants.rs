use bitcoin::{Amount, BlockHash};

use crypto_bigint::U256;

pub type VerifierChallenge = (BlockHash, U256, u8);

/// Dummy number of BitVM disprove scripts
pub const NUM_INTERMEDIATE_STEPS: usize = 100;

pub const KICKOFF_UTXO_AMOUNT_SATS: Amount = Amount::from_sat(100_000);

pub const KICKOFF_INPUT_AMOUNT: Amount = Amount::from_sat(100_000);
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330); // TODO: Maybe this could be 294, check
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(240); // TODO: This will change to 0 in the future after Bitcoin v0.29.0
pub const OPERATOR_CHALLENGE_AMOUNT: Amount = Amount::from_sat(200_000_000);
