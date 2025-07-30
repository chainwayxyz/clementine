//! # Hashes
//! Common hashing functions used in the Clementine protocol.
//! These functions include double SHA256 hashing, single SHA256 hashing, and a utility function to
//! hash two nodes together. They are essential for cryptographic operations in the bridge circuit and other
//! components of the protocol.

use sha2::{Digest, Sha256};

/// Calculates the double SHA256 hash of the input data.
pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

/// Calculates the SHA256 hash of the input data.
pub fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}

/// Utility function to hash two nodes together
pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
