#![no_main]
#![no_std]

use clementine_circuits::bridge::header_chain_proof;
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main); 

pub fn main() {
    let (method_id, genesis_block_hash, offset, blockhash, pow) = header_chain_proof::<RealEnvironment>();
    env::commit(&method_id);
    env::commit(&genesis_block_hash);
    env::commit(&offset);
    env::commit(&blockhash);
    env::commit(&pow);
}