#![no_main]
#![no_std]

use clementine_circuits::bridge::header_chain_proof;
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main); 

pub fn main() {
    let txid = header_chain_proof::<RealEnvironment>();
    env::commit(&5);
}