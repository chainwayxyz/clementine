use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

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

pub fn hash160(input: &[u8]) -> [u8; 20] {
    let hash = Sha256::digest(input);
    let hash = Ripemd160::digest(hash);
    hash.into()
}

#[cfg(test)]
mod tests {

    use super::*;
    use bitcoin::hashes::{self, Hash};

    #[test]
    fn test_hash160() {
        let message = "CITREA<->CLEMENTINE";
        let input = message.as_bytes();
        let expected = hashes::hash160::Hash::hash(input);
        let expected: &[u8; 20] = expected.as_byte_array();
        assert_eq!(hash160(input), *expected);
    }
}
