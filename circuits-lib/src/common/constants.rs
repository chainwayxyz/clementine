//! # Common Constants
//! Common constants used for Risc0 circuits in the Clementine protocol.
//! These constants are used across various modules to ensure consistency and correctness in the circuit operations.
//! They include constants for the number of outputs, transaction assertions, and watchtowers.
//! ## Header Chain Method IDs
//! These constants represent the method IDs for different network header chains, such as Mainnet, Testnet4, Signet, and Regtest.

/// The number of kickoff outputs before the first assert utxo.
pub const FIRST_FIVE_OUTPUTS: usize = 5;
/// The number of assertion transactions that a challenged operator should send.
pub const NUMBER_OF_ASSERT_TXS: usize = 33;
/// The theoretical maximum number of watchtowers that can be used in the Clementine protocol.
pub const MAX_NUMBER_OF_WATCHTOWERS: usize = 160;

// Header chain method IDs for different networks.
pub const MAINNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3117507468, 2870378349, 3727709254, 1474362300, 751278644, 3030335089, 3510416266, 2595014440,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1685513462, 3309550213, 1156649850, 1331433837, 3373006347, 1508474107, 464856343, 225414579,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3708258746, 2684548520, 3143010949, 3197706394, 2166808102, 3586245258, 1995079827, 1275171576,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3154972722, 960803990, 4242666710, 1490336826, 1789045654, 4250584739, 3667451556, 1538495496,
];
