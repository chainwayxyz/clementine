#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

use bridge_core::{calculate_double_sha256, BlockHeader};
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

pub fn main() {
    let block_header: BlockHeader = env::read();
    let data = block_header.as_bytes();
    let block_hash = calculate_double_sha256(&data);
    env::commit(&block_hash);
}
