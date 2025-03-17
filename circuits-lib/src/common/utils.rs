use num_bigint::BigUint;
use num_traits::Num;

pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}

#[cfg(test)]
mod tests {
    use super::*;

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
