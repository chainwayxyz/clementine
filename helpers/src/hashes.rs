use sha2::{Digest, Sha256};

use crate::config::Data;

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().try_into().unwrap()
}

pub fn sha256(a: Data, b: Data) -> Data {
    let mut c = [0_u8; 2 * 32];
    c[..32].copy_from_slice(&a);
    c[32..].copy_from_slice(&b);
    let mut hasher = Sha256::new();
    hasher.update(c);
    hasher.finalize().try_into().unwrap()
}
