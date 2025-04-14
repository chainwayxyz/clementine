use circuits_lib::{common, bridge_circuit::bridge_circuit};

/// The method ID for the work only circuit.
pub static WORK_ONLY_IMAGE_ID: [u8; 32] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            hex_literal::hex!("6a1839674dcb57d4d0b489d6992f36166b663b196ca84cd5db321c03cf038caa")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            hex_literal::hex!("7d671cfd5e307534b0d6a42338764f8f5ae1357b3d0d4004c62fa41e31c47b8d")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            hex_literal::hex!("f3109042039f5903a01d75540ea5e4f6d4c52091ec6f48e8bb30f155d5a04e25")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            hex_literal::hex!("c94b02cb475b18e2054b2a88fcc907a5c11699ee0095110f09c1cb38c9211edc")
        }
        None => {
            hex_literal::hex!("6a1839674dcb57d4d0b489d6992f36166b663b196ca84cd5db321c03cf038caa")
        }
        _ => panic!("Invalid network type"),
    }
};

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
