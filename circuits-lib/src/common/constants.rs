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
    333056676, 3335364922, 1715843161, 1776884884, 633737953, 1058826165, 2018209097, 1263114494,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3828515261, 664710577, 1521995829, 406663138, 2718830525, 2036445603, 423698575, 741690037,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    623600516, 4143002918, 682841568, 563507164, 2803949883, 2794250099, 3096763404, 648635764,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    797802915, 2343907199, 1061777526, 3873321708, 1629952169, 1836314910, 2102232307, 287986243,
];
