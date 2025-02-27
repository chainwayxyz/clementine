use circuits_lib::bridge_circuit::bridge_circuit::bridge_circuit;
use circuits_lib::bridge_circuit_core;
fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest);
}
