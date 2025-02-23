use work_only_guest::work_only_circuit;
fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    work_only_circuit(&zkvm_guest);
}
