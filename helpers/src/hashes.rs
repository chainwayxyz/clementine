use sha2::{Digest, Sha256};

use crate::constant::Data;


pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().try_into().unwrap()
}

pub fn sha256_64bytes(a: Data, b: Data) -> Data {
    let mut c = [0_u8; 2 * 32];
    c[..32].copy_from_slice(&a);
    c[32..].copy_from_slice(&b);
    let mut hasher = Sha256::new();
    hasher.update(c);
    hasher.finalize().try_into().unwrap()
}

pub fn sha256_32bytes(a: Data) -> Data {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.finalize().try_into().unwrap()
}

pub fn sha256_96bytes(a: Data, b: Data, c: Data) -> Data {
    let mut d = [0_u8; 3 * 32];
    d[..32].copy_from_slice(&a);
    d[32..64].copy_from_slice(&b);
    d[64..].copy_from_slice(&c);
    let mut hasher = Sha256::new();
    hasher.update(d);
    hasher.finalize().try_into().unwrap()
}
