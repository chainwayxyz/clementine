use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::btc::calculate_double_sha256;

const SCRIPT_SIG_MAX_SIZE: usize = 256; // Define a suitable max size
const SCRIPT_PUB_KEY_MAX_SIZE: usize = 256; // Define a suitable max size
const MAX_INPUTS: usize = 1; // Arbitrary fixed number of maximum inputs
const MAX_OUTPUTS: usize = 2; // Arbitrary fixed number of maximum outputs

#[derive(Debug, Clone, Copy)]
pub struct TxInput {
    prev_tx_hash: [u8; 32],
    output_index: u32,
    script_sig_size: u8,
    script_sig: [u8; SCRIPT_SIG_MAX_SIZE],
    sequence: u32,
}

impl TxInput {

    pub fn new(prev_tx_id: [u8; 32], output_index: u32, script_sig_size: u8, script_sig: [u8; SCRIPT_SIG_MAX_SIZE], sequence: u32) -> Self {
        Self {
            prev_tx_hash: prev_tx_id,
            output_index: output_index,
            script_sig_size: script_sig_size,
            script_sig: script_sig,
            sequence: sequence,
        }
    }

    pub fn as_bytes(&self) -> ([u8; 1024], usize) {
        let mut bytes = [0u8; 1024];
        let mut index = 0;
        bytes[index..index+32].copy_from_slice(&self.prev_tx_hash);
        index += 32;
        bytes[index..index+4].copy_from_slice(&self.output_index.to_le_bytes());
        index += 4;
        bytes[index..index+1].copy_from_slice(&self.script_sig_size.to_le_bytes());
        index += 1;
        bytes[index..index+self.script_sig_size as usize].copy_from_slice(&self.script_sig[..self.script_sig_size as usize]);
        index += self.script_sig_size as usize;
        bytes[index..index+4].copy_from_slice(&self.sequence.to_le_bytes());
        index += 4;
        (bytes, index)
    }

}

#[derive(Debug, Clone, Copy)]
pub struct TxOutput {
    value: u64,
    script_pub_key_size: u8,
    script_pub_key: [u8; SCRIPT_PUB_KEY_MAX_SIZE],
}

impl TxOutput {

    pub fn new(value: u64, script_pub_key_size: u8, script_pub_key: [u8; SCRIPT_PUB_KEY_MAX_SIZE]) -> Self {
        Self {
            value: value,
            script_pub_key_size: script_pub_key_size,
            script_pub_key: script_pub_key,
        }
    }

    pub fn serialize(&self) -> ([u8; 1024], usize) {
        let mut bytes = [0u8; 1024];
        let mut index = 0;
        bytes[index..index+8].copy_from_slice(&self.value.to_le_bytes());
        index += 8;
        bytes[index..index+1].copy_from_slice(&self.script_pub_key_size.to_le_bytes());
        index += 1;
        bytes[index..index+self.script_pub_key_size as usize].copy_from_slice(&self.script_pub_key[..self.script_pub_key_size as usize]);
        index += self.script_pub_key_size as usize;
        (bytes, index)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Transaction {
    version: i32,
    input_count: u8,
    inputs: [TxInput; MAX_INPUTS],
    output_count: u8,
    outputs: [TxOutput; MAX_OUTPUTS],
    lock_time: u32,
}

impl Transaction {
    pub fn new(version: i32, input_count: u8, inputs: [TxInput; MAX_INPUTS], output_count: u8, outputs: [TxOutput; MAX_OUTPUTS], lock_time: u32) -> Self {
        Self {
            version,
            input_count: input_count,
            inputs: inputs,
            output_count: output_count,
            outputs: outputs,
            lock_time: lock_time,
        }
    }

    // Add methods to set inputs and outputs as needed
    // Serialization and other functionalities would also be added here

    pub fn serialize(&self) -> ([u8; 1024], usize) {  // Fixed size array for simplicity
        let mut bytes = [0u8; 1024];
        let mut index = 0;
        bytes[index..index+4].copy_from_slice(&self.version.to_le_bytes());
        index += 4;
        bytes[index..index+1].copy_from_slice(&self.input_count.to_le_bytes());
        index += 1;
        for i in 0..self.input_count as usize {
            let (input_bytes, input_size) = self.inputs[i].as_bytes();
            bytes[index..index+input_size].copy_from_slice(&input_bytes[..input_size]);
            index += input_size;
        }
        bytes[index..index+1].copy_from_slice(&self.output_count.to_le_bytes());
        index += 1;
        for i in 0..self.output_count as usize {
            let (output_bytes, output_size) = self.outputs[i].serialize();
            bytes[index..index+output_size].copy_from_slice(&output_bytes[..output_size]);
            index += output_size;
        }
        bytes[index..index+4].copy_from_slice(&self.lock_time.to_le_bytes());
        index += 4;
        (bytes, index)
    }

    pub fn calculate_txid(&self) -> [u8; 32] {
        let (serialized_tx, size) = self.serialize();
        let preimage = &serialized_tx[..size];
        let hash = calculate_double_sha256(&preimage);
        hash
    }
}

