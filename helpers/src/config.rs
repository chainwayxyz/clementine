use lazy_static::lazy_static;

use crate::hashes::sha256;

// Types
pub type Data = [u8; 32];
pub type Path = [Data; DEPTH];

// Constants
pub const PERIOD3: u32 = 0; // 500
pub const N: u32 = 18; // 4096
pub const EMPTYDATA: Data = [0; 32];
pub const DEPTH: usize = 32;
pub const HASH_FUNCTION: fn(Data, Data) -> Data = sha256;

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
