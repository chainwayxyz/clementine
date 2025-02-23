use bridge_circuit_guest::winternitz_circuit;

fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    winternitz_circuit(&zkvm_guest);
}
