#![no_main]
#![no_std]

use clementine_circuits::{bitcoin::{read_preimages_and_calculate_commit_taproot, read_tx_and_calculate_txid}, bridge::{bridge_proof, bridge_proof_test}};
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main); 

pub fn main() {
    // let txid = read_tx_and_calculate_txid::<RealEnvironment>(None, None);
    // env::commit(&txid);
    // tracing::debug!("txid: {:?}", txid);
    let (commit_taproot_addr, claim_proof_tree_leaf) =
    read_preimages_and_calculate_commit_taproot::<RealEnvironment>();
    env::commit(&commit_taproot_addr);
    env::commit(&claim_proof_tree_leaf);
    tracing::debug!("COMMIT TAPROOT ADDR: {:?}", commit_taproot_addr);
    tracing::debug!("CLAIM PROOF TREE LEAF: {:?}", claim_proof_tree_leaf);
}