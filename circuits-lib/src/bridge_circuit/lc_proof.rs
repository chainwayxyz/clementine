//! # Light Client Proof Verifier
//! This module implements the light client proof verifier for the bridge circuit.
//! It includes functions to verify light client proofs and extracting the light client circuit output.

use super::{
    constants::{
        DEVNET_LC_IMAGE_ID, MAINNET_LC_IMAGE_ID, REGTEST_LC_IMAGE_ID, TESTNET_LC_IMAGE_ID,
    },
    structs::LightClientProof,
};
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use risc0_zkvm::guest::env;

pub const LC_IMAGE_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST_LC_IMAGE_ID,
        Some(network) if matches!(network.as_bytes(), b"signet") => DEVNET_LC_IMAGE_ID,
        Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET_LC_IMAGE_ID,
        Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET_LC_IMAGE_ID,
        None => MAINNET_LC_IMAGE_ID,
        _ => panic!("Unsupported BITCOIN_NETWORK environment variable"),
    }
};

/// Verifies the light client proof and returns the light client circuit output.
pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> LightClientCircuitOutput {
    let light_client_circuit_output: LightClientCircuitOutput =
        borsh::from_slice(light_client_proof.lc_journal.as_slice())
            .expect("Failed to deserialize light client circuit output");

    env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal).unwrap();

    assert_eq!(
        light_client_circuit_output.light_client_proof_method_id, LC_IMAGE_ID,
        "Light client proof method ID does not match expected LC_IMAGE_ID"
    );

    light_client_circuit_output
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_zkvm::Receipt;

    #[test]
    fn test_lc_proof_verifier() {
        let lcp_receipt_bytes = include_bytes!("../../test_data/lcp_receipt.bin");
        let lcp_receipt: Receipt = borsh::from_slice(lcp_receipt_bytes).unwrap();

        println!("LCP Receipt: {:?}", lcp_receipt.clone());

        lcp_receipt.verify(REGTEST_LC_IMAGE_ID).unwrap();
    }
}
