use num_bigint::BigUint;
use num_traits::Num;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn hash160(input: &[u8]) -> [u8; 20] {
    let hash = Sha256::digest(input);
    let hash = Ripemd160::digest(hash);
    hash.into()
}

pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{self, Hash};

    use super::*;

    #[test]
    fn test_hash160() {
        let message = "CITREA<->CLEMENTINE";
        let input = message.as_bytes();
        let expected = hashes::hash160::Hash::hash(input);
        let expected: &[u8; 20] = expected.as_byte_array();
        assert_eq!(hash160(input), *expected);
    }

    #[test]
    fn test_to_decimal() {
        assert_eq!(to_decimal("0"), Some("0".to_string()));
        assert_eq!(to_decimal("1"), Some("1".to_string()));
        assert_eq!(to_decimal("a"), Some("10".to_string()));
        assert_eq!(to_decimal("f"), Some("15".to_string()));
        assert_eq!(to_decimal("10"), Some("16".to_string()));
        assert_eq!(to_decimal("1f"), Some("31".to_string()));
        assert_eq!(to_decimal("100"), Some("256".to_string()));
        assert_eq!(to_decimal("1ff"), Some("511".to_string()));
        assert_eq!(to_decimal("citrea"), None);
    }
}
