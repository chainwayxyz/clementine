use crate::{btc::calculate_double_sha256, utils::from_hex_to_bytes};
use crate::pool::{BufferPool, TxInputPool, TxOutputPool};

#[derive(Debug, Clone, Copy)]
pub struct TxInput {
    pub prev_tx_hash: [u8; 32],
    pub output_index: u32,
    pub script_sig_size: u8,
    pub script_sig: BufferPool,
    pub sequence: u32,
}

impl TxInput {

    pub fn new(prev_tx_id: [u8; 32], output_index: u32, script_sig_size: u8, script_sig: BufferPool, sequence: u32) -> Self {
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
            script_sig: BufferPool::Zero([0]),
            sequence: 0,
        }
    }

    pub fn as_bytes(&self) -> (BufferPool, usize) {
        let total_length = 32 + 4 + 1 + self.script_sig_size as usize + 4;
        let mut bytes = BufferPool::new(total_length);
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
    pub script_pub_key: BufferPool,
}

impl TxOutput {

    pub fn new(value: u64, script_pub_key_size: u8, script_pub_key: BufferPool) -> Self {
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
            script_pub_key: BufferPool::Zero([0]),
        }
    }

    pub fn serialize(&self) -> (BufferPool, usize) {
        let total_length = 8 + 1 + self.script_pub_key_size as usize;
        let mut bytes = BufferPool::new(total_length);
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
pub struct Transaction {
    pub version: i32,
    pub input_count: u8,
    pub inputs: TxInputPool,
    pub output_count: u8,
    pub outputs: TxOutputPool,
    pub lock_time: u32,
}

impl Transaction {
    pub fn new(version: i32, input_count: u8, inputs: TxInputPool, output_count: u8, outputs: TxOutputPool, lock_time: u32) -> Self {
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
            inputs: TxInputPool::Empty([TxInput::empty(); 0]),
            output_count: 0,
            outputs: TxOutputPool::Empty([TxOutput::empty(); 0]),
            lock_time: 0,
        }
    }

    // Add methods to set inputs and outputs as needed
    // Serialization and other functionalities would also be added here

    pub fn serialize(&self) -> (BufferPool, usize) {  // Fixed size array for simplicity
        let total_length = 4 + 1 + self.input_count as usize * 41 + 1 + self.output_count as usize * 9 + 4;
        let mut bytes = BufferPool::new(total_length);
        let mut index = 0;
        bytes[index..index+4].copy_from_slice(&self.version.to_le_bytes());
        index += 4;
        bytes[index..index+1].copy_from_slice(&self.input_count.to_le_bytes());
        index += 1;
        for i in 0..self.input_count as usize {
            let (input_bytes, input_size) = self.inputs[i].as_bytes();
            bytes[index..index+input_size].copy_from_slice(&input_bytes[0..input_size]);
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

    pub fn check_first_output_valid(&self, address: &str) -> bool {
        let address_bytes = from_hex_to_bytes(address);
        &self.outputs[0].script_pub_key[2..self.outputs[0].script_pub_key_size as usize] == &address_bytes.0[0..address_bytes.1]
    }
}
        