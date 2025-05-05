use circuits_lib::{bridge_circuit::bridge_circuit, common};
use hex_literal::hex;

pub static WORK_ONLY_IMAGE_ID: [u8; 32] = match option_env!("BITCOIN_NETWORK") {
    Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET,
    Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET4,
    Some(network) if matches!(network.as_bytes(), b"signet") => SIGNET,
    Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST,
    None => MAINNET,
    _ => panic!("Invalid network type"),
};

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
