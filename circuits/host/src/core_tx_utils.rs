use serde::de::DeserializeOwned;
use serde::Serialize;

use circuit_helpers::core_tx::Transaction;
use circuit_helpers::core_tx::TxInput;
use circuit_helpers::core_tx::TxOutput;
use circuit_helpers::config::MAX_HEX_SIZE;
use circuit_helpers::config::MAX_INPUTS_COUNT;
use circuit_helpers::config::MAX_OUTPUTS_COUNT;
use circuit_helpers::config::MAX_SCRIPT_SIZE;

pub fn char_to_digit(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8) - b'0',
        'a'..='f' => (c as u8) - b'a' + 10,
        'A'..='F' => (c as u8) - b'A' + 10,
        _ => 0, // Error handling: Invalid character
    }
}

pub fn from_hex_to_bytes(input: &str) -> ([u8; MAX_HEX_SIZE], usize) {
    let mut result = [0u8; MAX_HEX_SIZE];
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < input.len() / 2 {
        result[index] = char_to_digit(input.chars().nth(index * 2).unwrap()) * 16
            + char_to_digit(input.chars().nth(index * 2 + 1).unwrap());
        index += 1;
    }
    (result, index)
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

pub fn from_hex_to_u8(input: &str) -> u8 {
    return char_to_digit(input.chars().nth(0).unwrap()) * 16
        + char_to_digit(input.chars().nth(1).unwrap());
}

pub fn from_le_bytes_to_u32(input: [u8; 4]) -> u32 {
    let mut result = 0u32;
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < 4 {
        result = result * 256 + input[3 - index] as u32;
        index += 1;
    }
    result
}

pub fn from_le_bytes_to_u64(input: [u8; 8]) -> u64 {
    let mut result = 0u64;
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < 8 {
        result = result * 256 + input[7 - index] as u64;
        index += 1;
    }
    result
}

pub fn byte_to_hex(byte: u8) -> [char; 2] {
    let hex_chars: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    let high_nibble = (byte >> 4) as usize; // Extract the high nibble
    let low_nibble = (byte & 0x0F) as usize; // Extract the low nibble

    [hex_chars[high_nibble], hex_chars[low_nibble]]
}

pub fn from_bytes_to_hex(input: [u8; 1024], size: usize) -> ([char; 2048], usize) {
    let mut result = [0 as char; 2048];
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < size {
        let hex = byte_to_hex(input[index]);
        result[index * 2] = hex[0];
        result[index * 2 + 1] = hex[1];
        index += 1;
    }
    (result, size)
}

pub fn char_array_to_str<'a>(
    output_buffer: &'a mut [u8],
    input_array: &'a [char; 2048],
    size: usize,
) -> Option<&'a str> {
    if size > output_buffer.len() || size > input_array.len() {
        return None; // size is too large
    }

    let mut index = 0;
    while index < size {
        output_buffer[index] = input_array[index] as u8;
        index += 1;
    }

    core::str::from_utf8(&output_buffer[..size]).ok()
}

pub fn from_hex_to_tx<const INPUTS_COUNT: usize, const OUTPUTS_COUNT: usize>(
    input: &str,
) -> Transaction<INPUTS_COUNT, OUTPUTS_COUNT, 221>
where
    [TxInput; INPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
    [TxOutput; OUTPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
{
    let mut index = 0;
    let version_hex = &input[0..8];
    let version_bytes = from_hex_to_bytes(version_hex);
    let version = from_le_bytes_to_u32(version_bytes.0[0..4].try_into().unwrap()) as i32;
    let mut hex_flag = "";
    index += 8;
    if &input[index..index + 2] == "00" {
        index += 2;
        hex_flag = &input[index..index + 2];
        index += 2;
    }
    let hex_input_count = &input[index..index + 2];
    let input_count = from_hex_to_u8(hex_input_count);
    index += 2;
    let mut inputs = [TxInput::empty(); MAX_INPUTS_COUNT as usize];
    for i in 0..input_count {
        let hex_tx_id = &input[index..index + 64];
        let tx_id = from_hex_to_bytes(hex_tx_id).0[0..32].try_into().unwrap();
        index += 64;
        let hex_output_index = &input[index..index + 8];
        index += 8;
        let output_index_bytes = from_hex_to_bytes(hex_output_index);
        let output_index =
            from_le_bytes_to_u32(output_index_bytes.0[0..4].try_into().unwrap()) as u32;
        let hex_script_sig_size = &input[index..index + 2];
        let script_sig_size = from_hex_to_u8(hex_script_sig_size);
        index += 2;
        let script_sig: [u8; MAX_SCRIPT_SIZE] =
            (from_hex_to_bytes(&input[index..index + (script_sig_size as usize) * 2]).0)
                [..MAX_SCRIPT_SIZE]
                .try_into()
                .unwrap();
        index += (script_sig_size as usize) * 2;
        let hex_sequence = &input[index..index + 8];
        index += 8;
        let sequence_bytes = from_hex_to_bytes(hex_sequence);
        let sequence = from_le_bytes_to_u32(sequence_bytes.0[0..4].try_into().unwrap()) as u32;
        let tx_in = TxInput::new(tx_id, output_index, sequence);
        inputs[i as usize] = tx_in;
    }
    let hex_output_count = &input[index..index + 2];
    let output_count = from_hex_to_u8(hex_output_count);
    index += 2;
    let mut outputs = [TxOutput::empty(); MAX_OUTPUTS_COUNT as usize];
    for i in 0..output_count {
        let hex_value = &input[index..index + 16];
        index += 16;
        let value_bytes = from_hex_to_bytes(hex_value);
        let value = from_le_bytes_to_u64(value_bytes.0[0..8].try_into().unwrap()) as u64;
        let hex_script_pub_key_size = &input[index..index + 2];
        let script_pub_key_size = from_hex_to_u8(hex_script_pub_key_size);
        index += 2;
        let script_pub_key: [u8; 34] =
            (from_hex_to_bytes(&input[index..index + (script_pub_key_size as usize) * 2]).0)
                [..MAX_SCRIPT_SIZE]
                .try_into()
                .unwrap();
        let taproot_address: [u8; 32] = script_pub_key[2..34].try_into().unwrap();
        index += (script_pub_key_size as usize) * 2;
        let tx_out = TxOutput::new(value, taproot_address);
        outputs[i as usize] = tx_out;
    }
    if hex_flag != "" {
        for _ in 0..input_count {
            let hex_witness_count = &input[index..index + 2];
            index += 2;
            let witness_count = from_hex_to_u8(hex_witness_count);
            for _i in 0..witness_count {
                let hex_witness_size = &input[index..index + 2];
                let witness_size = from_hex_to_u8(hex_witness_size);
                index += 2;
                let _witness =
                    from_hex_to_bytes(&input[index..index + (witness_size as usize) * 2]).0;
                index += (witness_size as usize) * 2;
            }
        }
    }
    let hex_locktime = &input[index..index + 8];
    index += 8;
    let locktime_bytes = from_hex_to_bytes(hex_locktime);
    let locktime = from_le_bytes_to_u32(locktime_bytes.0[0..4].try_into().unwrap()) as u32;
    Transaction {
        version,
        input_count,
        inputs: inputs[0..INPUTS_COUNT].try_into().unwrap(),
        output_count,
        outputs: outputs[0..OUTPUTS_COUNT].try_into().unwrap(),
        lock_time: locktime,
    }
}
