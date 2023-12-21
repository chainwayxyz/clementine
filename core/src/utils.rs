pub fn char_to_digit(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8) - b'0',
        'a'..='f' => (c as u8) - b'a' + 10,
        'A'..='F' => (c as u8) - b'A' + 10,
        _ => 0,  // Error handling: Invalid character
    }
}

pub fn from_hex_to_bytes(input: &str) -> ([u8; 64], usize) {
    let mut result = [0u8; 64];
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < input.len() / 2 {
        result[index] = char_to_digit(input.chars().nth(index * 2).unwrap()) * 16
            + char_to_digit(input.chars().nth(index * 2 + 1).unwrap());
        index += 1;
    };
    (result, index)
}

pub fn from_le_bytes_to_u32(input: [u8; 4]) -> u32 {
    let mut result = 0u32;
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < 4 {
        result = result * 256 + input[3 - index] as u32;
        index += 1;
    };
    result
}

pub fn from_be_bytes_to_u32(input: [u8; 4]) -> u32 {
    let mut result = 0u32;
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < 4 {
        result = result * 256 + input[index] as u32;
        index += 1;
    };
    result
}

pub fn from_le_bytes_to_u64(input: [u8; 8]) -> u64 {
    let mut result = 0u64;
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < 8 {
        result = result * 256 + input[7 - index] as u64;
        index += 1;
    };
    result
}