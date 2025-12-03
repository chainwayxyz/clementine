use circuits_lib::{
    bridge_circuit::{
        bridge_circuit,
        constants::{
            MAINNET_WORK_ONLY_METHOD_ID, REGTEST_WORK_ONLY_METHOD_ID, SIGNET_WORK_ONLY_METHOD_ID,
            TESTNET4_WORK_ONLY_METHOD_ID,
        },
    },
    common,
};

pub static WORK_ONLY_IMAGE_ID: [u8; 32] = match option_env!("BITCOIN_NETWORK") {
    Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET_WORK_ONLY_METHOD_ID,
    Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET4_WORK_ONLY_METHOD_ID,
    Some(network) if matches!(network.as_bytes(), b"signet") => SIGNET_WORK_ONLY_METHOD_ID,
    Some(network) if matches!(network.as_bytes(), b"regtest-test") => REGTEST_WORK_ONLY_METHOD_ID,
    None => MAINNET_WORK_ONLY_METHOD_ID,
    _ => panic!("Invalid network type"),
};

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
