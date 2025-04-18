use circuits_lib::{common, bridge_circuit::bridge_circuit};
use hex_literal::hex;

static MAINNET: [u8; 32] = hex!("f32e881ba4bbf8a5cc3fed7a6eca02c4f087bc1c9cafb0ae7d350fdab1230d6f");
static TESTNET4: [u8; 32] = hex!("6d104e43b3c55b70a47873edbbd22c8cf01b5fc77e5ff973ad8ba4b9cf3528dc");
static REGTEST: [u8; 32] = hex!("70e23c3d05a32e4577b4b91ff0891f3ade75a381b815f343c78eb18d08ffccf2");
static SIGNET: [u8; 32] = hex!("4672711a78b07166acd61c7d0f0c59d3f786562480d2f3ec780749544d04e000");

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
