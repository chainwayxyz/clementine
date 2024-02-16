pub fn char_to_digit(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8) - b'0',
        'a'..='f' => (c as u8) - b'a' + 10,
        'A'..='F' => (c as u8) - b'A' + 10,
        _ => 0, // Error handling: Invalid character
    }
}

pub fn from_hex64_to_bytes32(input: &str) -> [u8; 32] {
    assert_eq!(input.len(), 64);
    let mut result = [0u8; 32];
    let mut index = 0;
    while index < input.len() / 2 {
        result[index] = char_to_digit(input.chars().nth(index * 2).unwrap()) * 16
            + char_to_digit(input.chars().nth(index * 2 + 1).unwrap());
        index += 1;
    }
    return result;
}
