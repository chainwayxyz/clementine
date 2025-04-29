fn main() {
    let zkvm_guest = circuits_lib::common::zkvm::Risc0Guest::new();
    circuits_lib::header_chain::header_chain_circuit(&zkvm_guest);
}