use bitcoin::Amount;

/// The amount of the P2A anchor output.
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(240); // TODO: This will change to 0 in the future after Bitcoin v0.29.0

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330); // TODO: Maybe this could be 294, check

pub const BLOCKS_PER_WEEK: u16 = 6 * 24 * 7;
pub const BLOCKS_PER_DAY: u16 = 6 * 24;

pub const WINTERNITZ_LOG_D: u32 = 4;

pub const KICKOFF_BLOCKHASH_COMMIT_LENGTH: u32 = 20 * 2;

pub const KICKOFF_AMOUNT: Amount = Amount::from_sat(40_000);

/// The amount that should be paid to the operator to challenge them.
pub const OPERATOR_CHALLENGE_AMOUNT: Amount = Amount::from_sat(200_000_000);

