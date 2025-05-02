use circuits_lib::{bridge_circuit::bridge_circuit, common};
use hex_literal::hex;

static MAINNET: [u8; 32] = hex!("8a7962cb0fb94827ac2edb47f9d1816830d4210adc35789bd49eb0684a57dfa9");
static TESTNET4: [u8; 32] =
    hex!("4ead6ab0cb253d6c010e182fe1b02a9a55cc6a0ed8ba5d7bf517f891c7f454e9");
static REGTEST: [u8; 32] = hex!("bc7eaab34012f22e0b31f83caf6a299cf86792d181a8e192b94b06d681925f82");
static SIGNET: [u8; 32] = hex!("62f6e7c40afd4d9da55795a8cdffae63ef996e61c04e5ab2be45b2435a08b5d8");

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
