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
    3214881280, 1288224447, 3778112705, 1710798163, 440093295, 1914428519, 4238404167, 305612690,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2273221597, 1089229283, 4183757351, 1992736085, 1355952110, 2449781446, 4221481665, 1843491962,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1137926789, 665447489, 2713502374, 1427139709, 2484478745, 1924042257, 2813622661, 1521825513,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    786757209, 2443542186, 2740093473, 2408022870, 1669960462, 3269462223, 4082640566, 1115513041,
];
