use circuits_lib::{common, bridge_circuit::bridge_circuit};

pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("989b954057d63b52d47b4a8a01680557b9c3899e3c68ed47b1ec16b0101d20cb");

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
