//! # Common Constants
//! Common constants used for Risc0 circuits in the Clementine protocol.
//! These constants are used across various modules to ensure consistency and correctness in the circuit operations.
//! They include constants for the number of outputs, transaction assertions, and watchtowers.
//! ## Header Chain Method IDs
//! These constants represent the method IDs for different network header chains, such as Mainnet, Testnet4, Signet, and Regtest.

/// The number of kickoff outputs before the first assert utxo.
pub const FIRST_FIVE_OUTPUTS: usize = 5;
/// The number of assertion transactions that a challenged operator should send.
pub const NUMBER_OF_ASSERT_TXS: usize = 36;
/// The theoretical maximum number of watchtowers that can be used in the Clementine protocol.
pub const MAX_NUMBER_OF_WATCHTOWERS: usize = 160;

// Header chain method IDs for different networks.
pub const MAINNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    979737163, 3139115623, 434676403, 1033805265, 2367912767, 640592238, 952268029, 3887751414,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2487449420, 2186829733, 2515280211, 3828941899, 3409442174, 3966286449, 922629988, 1022921726,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    4072711430, 3526910400, 551000790, 1037364378, 1103702670, 2556721815, 1120182538, 4161994494,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1720128379, 2377242113, 951606047, 2583305317, 2941342008, 2869654011, 3094413664, 2824949714,
];
