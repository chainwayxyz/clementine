use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::hashes::calculate_double_sha256;

use crate::config::TX_INPUT_SIZE;
use crate::config::TX_OUTPUT_SIZE;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_tx_hash: [u8; 32],
    pub output_index: u32,
    pub sequence: u32,
}

impl TxInput {
    pub fn new(prev_tx_id: [u8; 32], output_index: u32, sequence: u32) -> Self {
        Self {
            prev_tx_hash: prev_tx_id,
            output_index: output_index,
            sequence: sequence,
        }
    }

    pub fn empty() -> Self {
        Self {
            prev_tx_hash: [0u8; 32],
            output_index: 0,
            sequence: 0,
        }
    }

    pub fn as_bytes(&self) -> [u8; TX_INPUT_SIZE] {
        let mut bytes = [0u8; TX_INPUT_SIZE];
        let mut index = 0;
        bytes[index..index + 32].copy_from_slice(&self.prev_tx_hash);
        index += 32;
        bytes[index..index + 4].copy_from_slice(&self.output_index.to_le_bytes());
        index += 4;
        bytes[index..index + 1].copy_from_slice(&0u8.to_le_bytes());
        index += 1;
        bytes[index..index + 4].copy_from_slice(&self.sequence.to_le_bytes());
        index += 4;
        bytes
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,
    // pub script_pub_key_size: u8,
    // pub script_opcode: u8,
    pub taproot_address: [u8; 32],
}

impl TxOutput {
    pub fn new(
        value: u64,
        // script_pub_key_size: u8,
        // script_opcode: u8,
        taproot_address: [u8; 32],
    ) -> Self {
        Self {
            value: value,
            // script_pub_key_size: script_pub_key_size,
            // script_opcode: script_opcode,
            taproot_address: taproot_address,
        }
    }

    pub fn empty() -> Self {
        Self {
            value: 0,
            // script_pub_key_size: 0,
            // script_opcode: 0,
            taproot_address: [0u8; 32],
        }
    }

    pub fn serialize(&self) -> [u8; TX_OUTPUT_SIZE] {
        let mut bytes = [0u8; TX_OUTPUT_SIZE];
        let mut index = 0;
        bytes[index..index + 8].copy_from_slice(&self.value.to_le_bytes());
        index += 8;
        bytes[index..index + 1].copy_from_slice(&34u8.to_le_bytes());
        index += 1;
        bytes[index..index + 1].copy_from_slice(&81u8.to_le_bytes()); // OP_PUSH_1
        index += 1;
        bytes[index..index + 1].copy_from_slice(&32u8.to_le_bytes()); // OP_PUSHBYTES_32
        index += 1;
        bytes[index..index + 32 as usize].copy_from_slice(&self.taproot_address);
        index += 32 as usize;
        bytes
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Transaction<
    const INPUTS_COUNT: usize,
    const OUTPUTS_COUNT: usize,
    const TOTAL_SIZE: usize,
> where
    [TxInput; INPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
    [TxOutput; OUTPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
{
    pub version: i32,
    pub input_count: u8,
    pub inputs: [TxInput; INPUTS_COUNT],
    pub output_count: u8,
    pub outputs: [TxOutput; OUTPUTS_COUNT],
    pub lock_time: u32,
}

impl<const INPUTS_COUNT: usize, const OUTPUTS_COUNT: usize, const TOTAL_SIZE: usize>
    Transaction<INPUTS_COUNT, OUTPUTS_COUNT, TOTAL_SIZE>
where
    [TxInput; INPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
    [TxOutput; OUTPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
{
    pub fn new(
        version: i32,
        input_count: u8,
        inputs: [TxInput; INPUTS_COUNT],
        output_count: u8,
        outputs: [TxOutput; OUTPUTS_COUNT],
        lock_time: u32,
    ) -> Self {
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

    pub fn serialize(&self) -> [u8; TOTAL_SIZE] {
        // Fixed size array for simplicity
        let mut bytes = [0u8; TOTAL_SIZE];
        let mut index = 0;
        bytes[index..index + 4].copy_from_slice(&self.version.to_le_bytes());
        index += 4;
        bytes[index..index + 1].copy_from_slice(&self.input_count.to_le_bytes());
        index += 1;
        for i in 0..self.input_count as usize {
            let input_bytes = self.inputs[i].as_bytes();
            bytes[index..index + TX_INPUT_SIZE].copy_from_slice(&input_bytes);
            index += TX_INPUT_SIZE;
        }
        bytes[index..index + 1].copy_from_slice(&self.output_count.to_le_bytes());
        index += 1;
        for i in 0..self.output_count as usize {
            let output_bytes = self.outputs[i].serialize();
            bytes[index..index + TX_OUTPUT_SIZE].copy_from_slice(&output_bytes);
            index += TX_OUTPUT_SIZE;
        }
        bytes[index..index + 4].copy_from_slice(&self.lock_time.to_le_bytes());
        index += 4;
        bytes
    }

    pub fn calculate_txid(&self) -> [u8; 32] {
        let serialized_tx = self.serialize();
        let hash = calculate_double_sha256(&serialized_tx);
        hash
    }
}
