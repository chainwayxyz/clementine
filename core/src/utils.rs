use crate::pool::{BufferPool, TxInputPool, TxOutputPool};
use crate::tx::Transaction;
use crate::tx::TxInput;
use crate::tx::TxOutput;

pub fn char_to_digit(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8) - b'0',
        'a'..='f' => (c as u8) - b'a' + 10,
        'A'..='F' => (c as u8) - b'A' + 10,
        _ => 0, // Error handling: Invalid character
    }
}

pub fn from_hex_to_bytes(input: &str) -> (BufferPool, usize) {
    let total_length = input.len() / 2;
    let mut result = BufferPool::new(total_length);
    let mut index = 0;

    // Iterate over each character pair in the input string
    while index < input.len() / 2 {
        result[index] = char_to_digit(input.chars().nth(index * 2).unwrap()) * 16
            + char_to_digit(input.chars().nth(index * 2 + 1).unwrap());
        index += 1;
    }
    (result, index)
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

pub fn from_hex_to_tx(input: &str) -> Transaction {
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
    let mut inputs = TxInputPool::new(input_count as usize);
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
        let script_sig: BufferPool =
            from_hex_to_bytes(&input[index..index + (script_sig_size as usize) * 2]).0;
        index += (script_sig_size as usize) * 2;
        let hex_sequence = &input[index..index + 8];
        index += 8;
        let sequence_bytes = from_hex_to_bytes(hex_sequence);
        let sequence = from_le_bytes_to_u32(sequence_bytes.0[0..4].try_into().unwrap()) as u32;
        let tx_in = TxInput::new(tx_id, output_index, script_sig_size, script_sig, sequence);
        inputs[i as usize] = tx_in;
    }
    let hex_output_count = &input[index..index + 2];
    let output_count = from_hex_to_u8(hex_output_count);
    index += 2;
    let mut outputs = TxOutputPool::new(output_count as usize);
    for i in 0..output_count {
        let hex_value = &input[index..index + 16];
        index += 16;
        let value_bytes = from_hex_to_bytes(hex_value);
        let value = from_le_bytes_to_u64(value_bytes.0[0..8].try_into().unwrap()) as u64;
        let hex_script_pub_key_size = &input[index..index + 2];
        let script_pub_key_size = from_hex_to_u8(hex_script_pub_key_size);
        index += 2;
        let script_pub_key =
            from_hex_to_bytes(&input[index..index + (script_pub_key_size as usize) * 2]).0;
        index += (script_pub_key_size as usize) * 2;
        let tx_out = TxOutput::new(value, script_pub_key_size, script_pub_key);
        outputs[i as usize] = tx_out;
    }
    if hex_flag != "" {
        let hex_witness_count = &input[index..index + 2];
        index += 2;
        let witness_count = from_hex_to_u8(hex_witness_count);
        for _i in 0..witness_count {
            let hex_witness_size = &input[index..index + 2];
            let witness_size = from_hex_to_u8(hex_witness_size);
            index += 2;
            let _witness = from_hex_to_bytes(&input[index..index + (witness_size as usize) * 2]).0;
            index += (witness_size as usize) * 2;
        }
    }
    let hex_locktime = &input[index..index + 8];
    index += 8;
    let locktime_bytes = from_hex_to_bytes(hex_locktime);
    let locktime = from_le_bytes_to_u32(locktime_bytes.0[0..4].try_into().unwrap()) as u32;
    Transaction {
        version,
        input_count,
        inputs,
        output_count,
        outputs,
        lock_time: locktime,
    }
}
