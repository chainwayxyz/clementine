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
    2955173012, 728051802, 601202369, 2015004770, 1859348607, 4082083865, 2229582381, 1239508114,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2523679475, 1934536817, 4225112399, 2762697194, 720040466, 1854092428, 81747755, 1071600261,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1903341033, 3132078220, 1964674125, 1914116332, 849879925, 789077400, 442800607, 3388504439,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3268223933, 3363847052, 443138915, 522720638, 2967177772, 2324565469, 4092943258, 1218520185,
];
