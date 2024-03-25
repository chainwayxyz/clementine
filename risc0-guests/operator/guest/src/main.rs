#![no_main]
#![no_std]

use clementine_circuits::bridge::bridge_proof;
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main); 

pub fn main() {
    let last_block_hash = bridge_proof::<RealEnvironment>();
    env::commit(&last_block_hash);
    tracing::debug!("last_block_hash: {:?}", last_block_hash);
}