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
    3988337386, 3527290003, 3056164372, 1827915447, 200589361, 2693538692, 3777329608, 3936971702,
];

pub const TESTNET4_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    389343877, 2483375134, 4068846859, 2827417147, 1922896383, 3932496489, 1451297543, 1925235144,
];

pub const SIGNET_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2342996253, 3885378862, 2074213603, 2743085460, 45982298, 258589637, 2336832315, 3457388605,
];

pub const REGTEST_HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    74075549, 1553883389, 1923147074, 4165044478, 3247420803, 17407152, 3734321480, 734859414,
];
