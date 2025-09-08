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
    2912371020, 898466567, 951945517, 1688774222, 674613396, 3062653244, 2551460527, 1554808323,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    730650438, 3739524508, 3338319342, 3835541806, 2462018058, 1662387233, 2269045293, 1574073106,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    3824550351, 1012719395, 16141748, 2883678659, 2006132380, 3906036021, 1229607079, 2199158102,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    1839650183, 766462249, 2625937566, 1272708886, 1850215338, 3199868349, 4002343765, 136147359,
];
