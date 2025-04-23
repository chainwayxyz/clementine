use circuits_lib::{common, bridge_circuit::bridge_circuit};
use hex_literal::hex;

static MAINNET: [u8; 32] = hex!("b237f3513a6ef4bbcec303d0e3363e3f7bb2ccd2487b58bd730f7dfce2a44d64");
static TESTNET4: [u8; 32] = hex!("49e267eafc5e424a11232fbd8e8fa084f77f07cf74352d4eab56c853565e2a66");
static REGTEST: [u8; 32] = hex!("0e43ec107a9f73f6d3446150503e4cec83254ab596ee21ebc2706b511237ba1b");
static SIGNET: [u8; 32] = hex!("d4c5c8b7e57df34fde68af32d8f90b42e25b72b490795cd164bc7fd0d6aee8a8");

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
