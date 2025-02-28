use circuits_lib::{bridge_circuit_core, bridge_circuit::bridge_circuit::bridge_circuit};

pub static PRE_STATE: [u8; 32] =
    hex_literal::hex!("1ca7d092fbc3233ba9910d5f60e593705a0aca14c325ff59500f407364e7f949");

fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, PRE_STATE);
}
