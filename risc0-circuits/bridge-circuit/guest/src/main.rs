use circuits_lib::{common, bridge_circuit::bridge_circuit};

pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("5e2ebb3cdbb2f6bfb9d3fcf27b87fbf229f1f29c3f4bb560e5dce31160cf3d5d");

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
