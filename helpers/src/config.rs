use lazy_static::lazy_static;

use crate::hashes::sha256_64bytes;
use bitcoin::Network;

// Types
pub type Data = [u8; 32];
pub type Path = [Data; DEPTH];

// Constants
pub const PERIOD3: u32 = 0; // 500
pub const N: u32 = 18; // 4096
pub const EMPTYDATA: Data = [0; 32];
pub const DEPTH: usize = 32;
pub const HASH_FUNCTION: fn(Data, Data) -> Data = sha256_64bytes;
pub const MAX_INPUTS_COUNT: u8 = 2;
pub const MAX_OUTPUTS_COUNT: u8 = 3;
pub const MAX_SCRIPT_SIZE: usize = 34;
pub const MAX_HEX_SIZE: usize = 1024;
pub const TX_INPUT_SIZE: usize = 41;
pub const TX_OUTPUT_SIZE: usize = 43;
pub const DUST: u64 = 546;
pub const FEE: u64 = 154;
pub const USER_TAKES_AFTER: u32 = 200;
pub const FED_TAKES_AFTER: u32 = 1000;
pub const REGTEST: Network = bitcoin::Network::Regtest;
pub const NUM_VERIFIERS: usize = 10;

// Zero subtree hashes
lazy_static! {
    pub static ref ZEROES: [Data; DEPTH + 1] = {
        let mut a = [EMPTYDATA; DEPTH + 1];
        for i in 0..DEPTH {
            a[i + 1] = HASH_FUNCTION(a[i], a[i]);
        }
        a
    };
}
