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
    3652626281, 3002766787, 3722627615, 4039790070, 4147537278, 1544178083, 1650283956, 1173916822,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1238069516, 2440952130, 296067507, 548718500, 2300908118, 2762236706, 1765400336, 2839141719,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    805076607, 3918709423, 1059613400, 4117586246, 1585144107, 652222522, 1455179921, 993675895,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1301496876, 1115288630, 3669357080, 2302899584, 2983230370, 2760464479, 2701535872, 2516705902,
];
