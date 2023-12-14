#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

use bridge_core::btc::{calculate_double_sha256, validate_threshold_and_add_work, BlockHeader};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);
use crypto_bigint::Encoding;
use crypto_bigint::U256;

pub fn main() {
    let n: u32 = env::read();
    let initial_work: [u8; 32] = env::read();
    let mut work = U256::from_be_bytes(initial_work);

    let mut block_hash: [u8; 32] = [0; 32];

    for _ in 0..n {
        let block_header: BlockHeader = env::read();

        let data = block_header.as_bytes();
        block_hash = calculate_double_sha256(&data);
        work = validate_threshold_and_add_work(block_header, block_hash, work);
    }
    env::commit(&block_hash);
    env::commit(&work.to_be_bytes());
}
