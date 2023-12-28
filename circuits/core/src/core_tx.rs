use crate::btc::calculate_double_sha256;
pub const MAX_INPUTS_COUNT: usize = 2;
pub const MAX_OUTPUTS_COUNT: usize = 3;
pub const MAX_SCRIPT_SIZE: usize = 256;
pub const MAX_TX_INPUT_SIZE: usize = 512;
pub const MAX_TX_OUTPUT_SIZE: usize = 512;
pub const MAX_TX_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct TxInput {
    pub prev_tx_hash: [u8; 32],
    pub output_index: u32,
    pub script_sig_size: u8,
    pub script_sig: [u8; MAX_SCRIPT_SIZE],
    pub sequence: u32,
}

impl TxInput {

    pub fn new(prev_tx_id: [u8; 32], output_index: u32, script_sig_size: u8, script_sig: [u8; MAX_SCRIPT_SIZE], sequence: u32) -> Self {
        Self {
            prev_tx_hash: prev_tx_id,
            output_index: output_index,
            script_sig_size: script_sig_size,
            script_sig: script_sig,
            sequence: sequence,
        }
    }

    pub fn empty() -> Self {
        Self {
            prev_tx_hash: [0u8; 32],
            output_index: 0,
            script_sig_size: 0,
            script_sig: [0u8; MAX_SCRIPT_SIZE],
            sequence: 0,
        }
    }

    pub fn as_bytes(&self) -> ([u8; MAX_TX_INPUT_SIZE], usize) {
        let mut bytes = [0u8; MAX_TX_INPUT_SIZE];
        let mut index = 0;
        bytes[index..index+32].copy_from_slice(&self.prev_tx_hash);
        index += 32;
        bytes[index..index+4].copy_from_slice(&self.output_index.to_le_bytes());
        index += 4;
        bytes[index..index+1].copy_from_slice(&self.script_sig_size.to_le_bytes());
        index += 1;
        bytes[index..index+self.script_sig_size as usize].copy_from_slice(&self.script_sig[0..self.script_sig_size as usize]);
        index += self.script_sig_size as usize;
        bytes[index..index+4].copy_from_slice(&self.sequence.to_le_bytes());
        index += 4;
        (bytes, index)
    }

}

#[derive(Debug, Clone, Copy)]
pub struct TxOutput {
    pub value: u64,
    pub script_pub_key_size: u8,
    pub script_pub_key: [u8; MAX_SCRIPT_SIZE],
}

impl TxOutput {

    pub fn new(value: u64, script_pub_key_size: u8, script_pub_key: [u8; MAX_SCRIPT_SIZE]) -> Self {
        Self {
            value: value,
            script_pub_key_size: script_pub_key_size,
            script_pub_key: script_pub_key,
        }
    }

    pub fn empty() -> Self {
        Self {
            value: 0,
            script_pub_key_size: 0,
            script_pub_key: [0u8; MAX_SCRIPT_SIZE],
        }
    }

    pub fn serialize(&self) -> ([u8; MAX_TX_OUTPUT_SIZE], usize) {
        let mut bytes = [0u8; MAX_TX_OUTPUT_SIZE];
        let mut index = 0;
        bytes[index..index+8].copy_from_slice(&self.value.to_le_bytes());
        index += 8;
        bytes[index..index+1].copy_from_slice(&self.script_pub_key_size.to_le_bytes());
        index += 1;
        bytes[index..index+self.script_pub_key_size as usize].copy_from_slice(&self.script_pub_key[0..self.script_pub_key_size as usize]);
        index += self.script_pub_key_size as usize;
        (bytes, index)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Transaction <const INPUTS_COUNT: usize, const OUTPUTS_COUNT: usize> {
    pub version: i32,
    pub input_count: u8,
    pub inputs: [TxInput; INPUTS_COUNT],
    pub output_count: u8,
    pub outputs: [TxOutput; OUTPUTS_COUNT],
    pub lock_time: u32,
}

impl <const INPUTS_COUNT: usize, const OUTPUTS_COUNT: usize> Transaction <INPUTS_COUNT, OUTPUTS_COUNT> {
    pub fn new(version: i32, input_count: u8, inputs: [TxInput; INPUTS_COUNT], output_count: u8, outputs: [TxOutput; OUTPUTS_COUNT], lock_time: u32) -> Self {
        Self {
            version,
            input_count: input_count,
            inputs: inputs,
            output_count: output_count,
            outputs: outputs,
            lock_time: lock_time,
        }
    }

    pub fn empty() -> Self {
        Self {
            version: 0,
            input_count: 0,
            inputs: [TxInput::empty(); INPUTS_COUNT],
            output_count: 0,
            outputs: [TxOutput::empty(); OUTPUTS_COUNT],
            lock_time: 0,
        }
    }

    // Add methods to set inputs and outputs as needed
    // Serialization and other functionalities would also be added here

    pub fn serialize(&self) -> ([u8; MAX_TX_SIZE], usize) {  // Fixed size array for simplicity
        let mut bytes: [u8; 1024] = [0; MAX_TX_SIZE];
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
            bytes[index..index+output_size].copy_from_slice(&output_bytes[0..output_size]);
            index += output_size;
        }
        bytes[index..index+4].copy_from_slice(&self.lock_time.to_le_bytes());
        index += 4;
        (bytes, index)
    }

    pub fn calculate_txid(&self) -> [u8; 32] {
        let (serialized_tx, size) = self.serialize();
        let preimage = &serialized_tx[0..size];
        let hash = calculate_double_sha256(&preimage);
        hash
    }

}
        