use bridge_circuit_lib::bridge_circuit;

fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest);
}
