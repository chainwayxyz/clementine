#![no_main]
sp1_zkvm::entrypoint!(main);
use circuits_lib::common;
use circuits_lib::work_only::work_only_circuit;
fn main() {
    let zkvm_guest = common::sp1::SP1Guest;
    work_only_circuit(&zkvm_guest);
}
