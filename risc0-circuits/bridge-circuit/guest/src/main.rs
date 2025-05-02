use circuits_lib::{bridge_circuit::bridge_circuit, common};
use hex_literal::hex;

static MAINNET: [u8; 32] = hex!("5a9fa44f3868f374e8c6b9eb2c48c0a154121ac7f6ab31458ad082926c47eef1");
static TESTNET4: [u8; 32] =
    hex!("48173e79093e43d0541d852f8c4e20c879a8258a1b074936d424f192a7e712e2");
static REGTEST: [u8; 32] = hex!("38d5e9588e08259828fd658c2966c1c0e543031955a8f1645e539f2931f3ad12");
static SIGNET: [u8; 32] = hex!("ef04b7717674317deb9c9b2cbc185f0af2790c19a447c19f5883bf3d986bbc64");

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
