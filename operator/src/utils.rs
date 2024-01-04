use std::io::{self, Write};

use bitcoin;

use bitcoin::consensus::Decodable;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use serde::de::DeserializeOwned;
use serde::Serialize;

use circuit_helpers::core_tx::Transaction;
use circuit_helpers::core_tx::TxInput;
use circuit_helpers::core_tx::TxOutput;

use byteorder::{ByteOrder, LittleEndian};
use hex;
use circuit_helpers::config::MAX_INPUTS_COUNT;
use circuit_helpers::config::MAX_OUTPUTS_COUNT;
use circuit_helpers::config::MAX_SCRIPT_SIZE;

pub fn take_stdin<T: std::str::FromStr>(prompt: &str) -> Result<T, T::Err> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut string = String::new();
    io::stdin()
        .read_line(&mut string)
        .expect("Failed to read line");

    string.trim().parse::<T>()
}

pub fn char_to_digit(c: char) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(&c.to_string(), 16)
}

pub fn from_hex_to_bytes(input: &str) -> Vec<u8> {
    hex::decode(input).unwrap()
}

pub fn from_hex64_to_bytes32(input: &str) -> [u8; 32] {
    hex::decode(input)
        .unwrap()
        .try_into()
        .expect("Slice with incorrect length")
}

pub fn from_hex_to_u8(input: &str) -> u8 {
    let bytes = hex::decode(input).unwrap();
    bytes[0]
}

pub fn from_le_bytes_to_u32(input: &[u8]) -> u32 {
    LittleEndian::read_u32(input)
}

pub fn from_le_bytes_to_u64(input: &[u8]) -> u64 {
    LittleEndian::read_u64(input)
}

pub fn byte_to_hex(byte: u8) -> String {
    hex::encode([byte])
}

pub fn from_bytes_to_hex(input: &[u8]) -> String {
    hex::encode(input)
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
    let version = from_le_bytes_to_u32(version_bytes[0..4].try_into().unwrap()) as i32;
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
        let tx_id = from_hex_to_bytes(hex_tx_id)[0..32].try_into().unwrap();
        index += 64;
        let hex_output_index = &input[index..index + 8];
        index += 8;
        let output_index_bytes = from_hex_to_bytes(hex_output_index);
        let output_index =
            from_le_bytes_to_u32(output_index_bytes[0..4].try_into().unwrap()) as u32;
        let hex_script_sig_size = &input[index..index + 2];
        let script_sig_size = from_hex_to_u8(hex_script_sig_size);
        index += 2;
        index += (script_sig_size as usize) * 2;
        let hex_sequence = &input[index..index + 8];
        index += 8;
        let sequence_bytes = from_hex_to_bytes(hex_sequence);
        let sequence = from_le_bytes_to_u32(sequence_bytes[0..4].try_into().unwrap()) as u32;
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
        let value = from_le_bytes_to_u64(value_bytes[0..8].try_into().unwrap()) as u64;
        let hex_script_pub_key_size = &input[index..index + 2];
        let script_pub_key_size = from_hex_to_u8(hex_script_pub_key_size);
        index += 2;
        let script_pub_key: [u8; 34] =
            from_hex_to_bytes(&input[index..index + (script_pub_key_size as usize) * 2])
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
                    from_hex_to_bytes(&input[index..index + (witness_size as usize) * 2]);
                index += (witness_size as usize) * 2;
            }
        }
    }
    let hex_locktime = &input[index..index + 8];
    let locktime_bytes = from_hex_to_bytes(hex_locktime);
    let locktime = from_le_bytes_to_u32(locktime_bytes[0..4].try_into().unwrap()) as u32;
    Transaction {
        version,
        input_count,
        inputs: inputs[0..INPUTS_COUNT].try_into().unwrap(),
        output_count,
        outputs: outputs[0..OUTPUTS_COUNT].try_into().unwrap(),
        lock_time: locktime,
    }
}

pub fn parse_hex_to_btc_tx(
    tx_hex: &str,
) -> Result<bitcoin::blockdata::transaction::Transaction, bitcoin::consensus::encode::Error> {
    if let Ok(reader) = hex::decode(tx_hex) {
        bitcoin::blockdata::transaction::Transaction::consensus_decode(&mut &reader[..])
    } else {
        Err(bitcoin::consensus::encode::Error::ParseFailed(
            "Could not decode hex",
        ))
    }
}


// Dummy function to generate a block with given transactions
pub fn generate_dummy_block(rpc: &Client) -> Vec<bitcoin::BlockHash> {
    // Use `generatetoaddress` or similar RPC method to mine a new block
    // containing the specified transactions
    let address = rpc.get_new_address(None, None).unwrap().assume_checked();
    // txs.iter().for_each(|tx| {
    //     rpc.send_raw_transaction(tx).unwrap();
    // });
    for _ in 0..10 {
        let new_address = rpc.get_new_address(None, None).unwrap().assume_checked();
        let amount = bitcoin::Amount::from_sat(1000); // Specify the amount to send
        rpc
            .send_to_address(&new_address, amount, None, None, None, None, None, None)
            .unwrap();
    }
    rpc.generate_to_address(1, &address).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::utils::{from_hex_to_tx, parse_hex_to_btc_tx};

    #[test]
    fn test_from_hex_to_tx_calculate_tx_id() {
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let tx = from_hex_to_tx::<2, 3>(input);
        let tx_id = tx.calculate_txid();
        let hex = hex::encode(tx_id);
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        let btc_hex = hex::encode(btc_tx_id);
        assert_eq!(btc_hex, hex);
    }
}
