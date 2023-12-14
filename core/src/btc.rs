use crate::BlockHeader;
use crypto_bigint::AddMod;
use crypto_bigint::U256;
use crypto_bigint::Pow;
use crypto_bigint::PowBoundedExp;
use crypto_bigint::Encoding;

pub fn calculate_work(bits: [u8; 4]) -> U256 {
    let target = decode_compact_target(bits);
    let target = U256::from_be_bytes(target);
    let target = target.pow(&U256::from(256));
    let target = target / U256::from(2u32.pow(208));
    target
}

pub fn validate_threshold(block_header: BlockHeader, block_hash: [u8; 32]) {
    // Step 1: Decode the target from the 'bits' field
    let target = decode_compact_target(block_header.bits);

    // Step 2: Compare the block hash with the target
    check_hash_valid(block_hash, target);

    // Step 3: Calculate work
    let work = calculate_work(block_header.bits);
}

fn decode_compact_target(bits: [u8; 4]) -> [u8; 32] {
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
    for i in 0..32 {
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
