use circuits_lib::{common, bridge_circuit::bridge_circuit};

pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("88c972d1d881135ce6135824ddbe354715c8d1b9ae8468dee438416eba3a3d4f");

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
