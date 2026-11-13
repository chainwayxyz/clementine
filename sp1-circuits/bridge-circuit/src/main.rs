#![no_main]
sp1_zkvm::entrypoint!(main);
use circuits_lib::{bridge_circuit::bridge_circuit, common};

fn main() {
    let zkvm_guest = common::sp1::SP1Guest;
    bridge_circuit(&zkvm_guest, common::programs::CURRENT_WORK_ONLY.groth16);
}
