#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

use bridge_core::{calculate_double_sha256, BlockHeader, blockheader_to_bytes};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
risc0_zkvm::guest::entry!(main);

pub fn main() {
    let block_header: BlockHeader = env::read();
    let data = blockheader_to_bytes(&block_header);
    let block_hash = calculate_double_sha256(&data);
    env::commit(&block_hash);
}
