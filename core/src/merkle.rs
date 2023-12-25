use sha2::{Digest, Sha256};
use lazy_static::lazy_static;

pub type Data = [u8; 32];
pub const EMPTYDATA: Data = [0; 32];
pub const DEPTH: usize = 32;
pub type Path = [Data; DEPTH];
pub const HASH_FUNCTION: fn(Data, Data) -> Data = sha256;

lazy_static! {
    pub static ref ZEROES: [Data; DEPTH + 1] = {
        let mut a = [EMPTYDATA; DEPTH + 1];
        for i in 0..DEPTH {
            a[i + 1] = HASH_FUNCTION(a[i], a[i]);
        }
        a
    };
}

pub fn sha256(a: Data, b: Data) -> Data {
    let mut c = [0_u8; 2 * 32];
    c[..32].copy_from_slice(&a);
    c[32..].copy_from_slice(&b);
    let mut hasher = Sha256::new();
    hasher.update(c);
    hasher.finalize().try_into().unwrap()
}
