#![no_main]
#![no_std]

use clementine_circuits::{bitcoin::read_tx_and_calculate_txid, bridge::bridge_proof};
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main); 

pub fn main() {
    // let txid = read_tx_and_calculate_txid::<RealEnvironment>(None, None);
    // env::commit(&txid);
    let res = bridge_proof::<RealEnvironment>();
    // env::commit(&res);
}