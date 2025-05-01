use circuits_lib::{bridge_circuit::bridge_circuit, common};
use hex_literal::hex;

static MAINNET: [u8; 32] = hex!("eba453abcce5f8b738e9a21ee9627ca02249cd502696198cb7c0214a2d4fbfbb");
static TESTNET4: [u8; 32] =
    hex!("311814c7ed8ef68979d93f2f91ac0e28ebe2916e3b0f69c31c01b46f4b41d9cb");
static REGTEST: [u8; 32] = hex!("38e85ae5013a9849a2367122b64ac45d6c893df331b264f138e4295f59254a5a");
static SIGNET: [u8; 32] = hex!("955d95c0722625eebfe2502459fe97e81d488faa49213ef015694917c9e3ae98");

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
