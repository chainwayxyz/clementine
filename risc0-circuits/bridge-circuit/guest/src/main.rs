use circuits_lib::{common, bridge_circuit::bridge_circuit};

pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("74ff37ef63067e274b964f368c66f137d7ac19739c14b7a214314998bc56df84");

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
