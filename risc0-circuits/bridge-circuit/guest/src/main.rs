use circuits_lib::{bridge_circuit_core, bridge_circuit::bridge_circuit::bridge_circuit};

pub static PRE_STATE: [u8; 32] =
    hex_literal::hex!("0e5538994223302b19029d4703ad72ed6feff8bb3c8f6e3cb64f6b3efcb08344");

fn main() {
    let zkvm_guest = bridge_circuit_core::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, PRE_STATE);
}
