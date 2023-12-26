#[cfg(test)]
mod tests {
    use bridge_core::utils::*;
    use bridge_core::tx::*;
    use bridge_core::btc::*;
    use bridge_core::vector::*;

    #[test]
    fn test_char_to_digit() {

    }

    #[test]
    fn test_from_hex_to_bytes() {

    }

    #[test]
    fn test_from_hex_to_u8() {

    }

    #[test]
    fn test_from_le_bytes_to_u32() {

    }

    #[test]
    fn test_from_le_bytes_to_u64() {

    }

    #[test]
    fn test_from_hex_to_tx() {

    }

    #[test]
    fn test_tx_input() {

    }

    #[test]
    fn test_tx_output() {

    }

    #[test]
    fn test_tx() {

    }

    #[test]
    fn test_tx_serialize() {

    }

    #[test]
    fn test_tx_calculate_tx_id() {

    }

    #[test]
    fn test_char_array_to_str() {
        let mut output_buffer = [0u8; 2048];
        let input_array = ['a'; 2048];
        let size = 2048;
        let result = char_array_to_str(&mut output_buffer, &input_array, size).unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_vector() {
        let mut vec = Vector::new();
        vec.push(1);
        vec.push(2);
        vec.push(3);
        println!("{:?}", vec);
    }
    
}