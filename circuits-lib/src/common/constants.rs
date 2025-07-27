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
    1571787042, 1135350460, 5504205, 2001289997, 217354967, 761521740, 4054432751, 2413281109,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2376769743, 2598389259, 476752603, 1027471519, 1079207740, 89127212, 2735298871, 486795673,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2853455480, 984811028, 703356843, 322547666, 258920033, 2343717533, 203306495, 1480683150,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3999867678, 1238801104, 2193481248, 2000578666, 592040546, 3056843199, 175638314, 589861740,
];
