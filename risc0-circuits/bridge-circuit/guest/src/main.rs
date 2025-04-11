use circuits_lib::{common, bridge_circuit::bridge_circuit};

/// The method ID for the work only circuit.
pub static WORK_ONLY_IMAGE_ID: [u8; 32] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            hex_literal::hex!("9c67e91726c38fa738d621e18da6bf1d683396911421de26d8f024a2c882a1c6")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            hex_literal::hex!("35752a194ac7350f0e598205b1c2a0ce814d236d98fb6442002d07121241b524")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            hex_literal::hex!("9e33cbed4101a4dcbe899498c73f592e5c89536e2a69632888b9f3b301bbc30e")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            hex_literal::hex!("426058be31d894c9a6296018fe7dfeeef361087400b2fd111b9df50d444eabbc")
        }
        None => {
            hex_literal::hex!("9c67e91726c38fa738d621e18da6bf1d683396911421de26d8f024a2c882a1c6")
        }
        _ => panic!("Invalid network type"),
    }
};

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
