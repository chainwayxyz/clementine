use lazy_static::lazy_static;

use crate::{
    constant::{Data, EMPTYDATA},
    sha256_hash,
};

// Types
pub type Path = [Data; DEPTH];

// Constants
pub const PERIOD3: u32 = 0; // 500
pub const N: u32 = 18; // 4096
pub const DEPTH: usize = 32;
pub const MAX_INPUTS_COUNT: u8 = 2;
pub const MAX_OUTPUTS_COUNT: u8 = 3;
pub const MAX_SCRIPT_SIZE: usize = 34;
pub const MAX_HEX_SIZE: usize = 1024;
pub const TX_INPUT_SIZE: usize = 41;
pub const TX_OUTPUT_SIZE: usize = 43;
pub const USER_TAKES_AFTER: u32 = 200;
pub const FED_TAKES_AFTER: u32 = 1000;
pub const NUM_VERIFIERS: usize = 4;
pub const NUM_USERS: usize = 4;
pub const BRIDGE_AMOUNT_SATS: u64 = 100_000_000;
pub const NUM_ROUNDS: usize = 4;
pub const CONNECTOR_TREE_OPERATOR_TAKES_AFTER: u16 = 1;
pub const CONNECTOR_TREE_DEPTH: usize = 4;

// Zero subtree hashes
lazy_static! {
    pub static ref ZEROES: [Data; DEPTH + 1] = {
        let mut a = [EMPTYDATA; DEPTH + 1];
        for i in 0..DEPTH {
            a[i + 1] = sha256_hash!(a[i], a[i]);
        }
        a
    };
}
