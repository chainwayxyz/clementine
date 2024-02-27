#![no_main]
#![no_std]

use circuit_helpers::bitcoin::read_tx_and_calculate_txid;
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main); 

pub fn main() {
    let txid = read_tx_and_calculate_txid::<RealEnvironment>(None, None);
    env::commit(&txid);
}