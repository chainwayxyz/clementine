use circuits_lib::work_only::work_only_circuit;
use circuits_lib::common;
fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    work_only_circuit(&zkvm_guest);
}
