use circuits_lib::work_only::work_only::work_only_circuit;
use circuits_lib::bridge_circuit_core;
fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    work_only_circuit(&zkvm_guest);
}
