pub mod common;
pub mod operator;
pub mod watchtower;

use common::zkvm::ZkvmGuest;
// use operator::{OperatorCircuitInput, OperatorCircuitOutput};
// use watchtower::{WatchtowerCircuitInput, WatchtowerCircuitOutput};
pub use risc0_zkvm;

pub fn operator_circuit(_guest: &impl ZkvmGuest) {
    // let start = risc0_zkvm::guest::env::cycle_count();
    // let input: OperatorCircuitInput = guest.read_from_host();
    // TODO: Implement operator circuit
    // guest.commit(&OperatorCircuitOutput {});
    // let end = risc0_zkvm::guest::env::cycle_count();
    // println!("Operator circuit took {:?} cycles", end - start);
}

pub fn watchtower_circuit(_guest: &impl ZkvmGuest) {
    // let start = risc0_zkvm::guest::env::cycle_count();
    // let input: WatchtowerCircuitInput = guest.read_from_host();
    // TODO: Implement watchtower circuit
    // guest.commit(&WatchtowerCircuitOutput {});
    // let end = risc0_zkvm::guest::env::cycle_count();
    // println!("Operator circuit took {:?} cycles", end - start);
}
