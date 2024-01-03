use crypto_bigint::Encoding;
use crypto_bigint::U256;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockHeader {
    pub version: [u8; 4],
    pub previous_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: [u8; 4],
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
}

impl BlockHeader {
    pub fn from_slice(input: &[u8; 80]) -> Self {
        BlockHeader {
            version: input[0..4].try_into().unwrap(),
            previous_block_hash: input[4..36].try_into().unwrap(),
            merkle_root: input[36..68].try_into().unwrap(),
            timestamp: input[68..72].try_into().unwrap(),
            bits: input[72..76].try_into().unwrap(),
            nonce: input[76..80].try_into().unwrap(),
        }
    }

    pub fn as_bytes(&self) -> [u8; 80] {
        let mut output: [u8; 80] = [0; 80];
        output[0..4].copy_from_slice(&self.version);
        output[4..36].copy_from_slice(&self.previous_block_hash);
        output[36..68].copy_from_slice(&self.merkle_root);
        output[68..72].copy_from_slice(&self.timestamp);
        output[72..76].copy_from_slice(&self.bits);
        output[76..80].copy_from_slice(&self.nonce);
        output
    }
}

pub fn validate_threshold_and_add_work(
    block_header: BlockHeader,
    block_hash: [u8; 32],
    old_work: U256,
) -> U256 {
    // Step 1: Decode the target from the 'bits' field
    let target = decode_compact_target(block_header.bits);

    // Step 2: Compare the block hash with the target
    check_hash_valid(block_hash, target);

    // Step 3: Calculate work
    let work = calculate_work(target);

    old_work.wrapping_add(&work)
}

pub fn decode_compact_target(bits: [u8; 4]) -> [u8; 32] {
    let mut bits = bits;
    bits.reverse();

    let mut target = [0u8; 32];
    let exponent = bits[0] as usize;
    let value = ((bits[1] as u32) << 16) | ((bits[2] as u32) << 8) | (bits[3] as u32);

    if exponent <= 3 {
        // If the target size is 3 bytes or less, place the value at the end
        let start_index = 4 - exponent;
        for i in 0..exponent {
            target[31 - i] = (value >> (8 * (start_index + i))) as u8;
        }
    } else {
        // If the target size is more than 3 bytes, place the value at the beginning and shift accordingly
        for i in 0..3 {
            target[exponent - 3 + i] = (value >> (8 * i)) as u8;
        }
    }

    target
}

fn check_hash_valid(hash: [u8; 32], target: [u8; 32]) {
    // for loop from 31 to 0
    for i in  (0..32).rev() {
        if hash[i] < target[i] {
            // The hash is valid because a byte in hash is less than the corresponding byte in target
            return;
        } else if hash[i] > target[i] {
            // The hash is invalid because a byte in hash is greater than the corresponding byte in target
            panic!("Hash is not valid");
        }
        // If the bytes are equal, continue to the next byte
    }
    // If we reach this point, all bytes are equal, so the hash is valid
}

pub fn calculate_work(target: [u8; 32]) -> U256 {
    let target_plus_one = U256::from_le_bytes(target).saturating_add(&U256::ONE);
    let work = U256::MAX.wrapping_div(&target_plus_one);
    work
}
