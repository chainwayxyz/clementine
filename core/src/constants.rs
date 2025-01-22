use bitcoin::Amount;
// TODO: Add the usual suspects here later (CONFIRMATION BLOCK COUNT, CONNECTOR UTXO AMOUNT, etc.)

// Dummy number of BitVM disprove scripts.
pub const NUM_INTERMEDIATE_STEPS: usize = 100;

/// The number of parallel `assert_tx`s sent by the operator. The flow is as follows:
/// 1. The operator sends `assert_begin_tx`
/// 2. For each output, the operator sends `assert_tx` spending that output and chains these transactions.
/// 3. The operator sends `assert_end_tx` to finalize the chain.
pub const PARALLEL_ASSERT_TX_CHAIN_SIZE: usize = 10;

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330); // TODO: Maybe this could be 294, check

/// The amount of the P2A anchor output.
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(240); // TODO: This will change to 0 in the future after Bitcoin v0.29.0

/// The amount that should be paid to the operator to challenge them.
pub const OPERATOR_CHALLENGE_AMOUNT: Amount = Amount::from_sat(200_000_000);
