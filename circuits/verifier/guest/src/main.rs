#![no_main]
#![no_std]

use circuit_helpers::bitcoin::{validate_threshold_and_add_work, BlockHeader};
use circuit_helpers::config::{N, PERIOD3};
use circuit_helpers::hashes::calculate_double_sha256;
use crypto_bigint::Encoding;
use crypto_bigint::U256;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let initial_block_hash: [u8; 32] = env::read();
    let initial_work: [u8; 32] = env::read();
    let mut previous_block_hash = initial_block_hash;
    previous_block_hash.reverse();
    let mut work = U256::from_be_bytes(initial_work);

    for _ in N..N + PERIOD3 {
        let block_header: BlockHeader = env::read();
        assert_eq!(block_header.previous_block_hash, previous_block_hash);
        let data = &block_header.as_bytes();
        let block_hash = calculate_double_sha256(data);
        work = validate_threshold_and_add_work(block_header, block_hash, work);
        previous_block_hash = block_hash;
    }

    // Inputs:
    env::commit(&initial_block_hash);
    env::commit(&initial_work);
    // Outputs:
    env::commit(&previous_block_hash);
    env::commit(&work.to_be_bytes());
}
