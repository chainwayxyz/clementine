use circuits_lib::{common, bridge_circuit::bridge_circuit};

pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("ca1ad948a8f4c8b2d8144ef2dcb4f863f31e13e1b0ffe803e81080f3c1128359");

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
