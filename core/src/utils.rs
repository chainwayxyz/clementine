pub fn char_to_digit(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8) - b'0',
        'a'..='f' => (c as u8) - b'a' + 10,
        'A'..='F' => (c as u8) - b'A' + 10,
        _ => 0,  // Error handling: Invalid character
    }
}

pub fn parse_str(input: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < input.len() / 2 {
        let pos = index * 2;
        let byte = (char_to_digit(input.chars().nth(pos).unwrap()), char_to_digit(input.chars().nth(pos + 1).unwrap()));
        result[index] = byte.0 * 16 + byte.1;
        index += 1;
    };
    result
}