//! # Light Client Proof Verifier
//! This module implements the light client proof verifier for the bridge circuit.
//! It includes functions to verify light client proofs and extracting the light client circuit output.

use super::{
    constants::{
        DEVNET_LC_IMAGE_ID, MAINNET_LC_IMAGE_ID, REGTEST_LC_IMAGE_ID, TESTNET4_LC_IMAGE_ID,
    },
    structs::LightClientProof,
};
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use risc0_zkvm::guest::env;

pub const LC_IMAGE_ID: [u8; 32] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST_LC_IMAGE_ID,
        Some(network) if matches!(network.as_bytes(), b"signet") => DEVNET_LC_IMAGE_ID,
        Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET4_LC_IMAGE_ID,
        Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET_LC_IMAGE_ID,
        None => MAINNET_LC_IMAGE_ID,
        _ => panic!("Unsupported BITCOIN_NETWORK environment variable"),
    }
};

/// Verifies the light client proof and returns the light client circuit output.
pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> LightClientCircuitOutput {
    env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal).unwrap();

    let light_client_circuit_output: LightClientCircuitOutput =
        borsh::from_slice(light_client_proof.lc_journal.as_slice())
            .expect("Failed to deserialize light client circuit output");

    assert!(
        check_method_id(&light_client_circuit_output, LC_IMAGE_ID),
        "Light client proof method ID does not match the expected LC image ID"
    );

    light_client_circuit_output
}

pub fn check_method_id(
    light_client_circuit_output: &LightClientCircuitOutput,
    lc_image_id_circuit: [u8; 32],
) -> bool {
    let light_client_method_id_bytes: [u8; 32] = light_client_circuit_output
        .light_client_proof_method_id
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Conversion from [u32; 8] to [u8; 32] cannot fail");

    light_client_method_id_bytes == lc_image_id_circuit
}

#[cfg(test)]
mod tests {

    use super::*;
    use risc0_zkvm::Receipt;

    #[test]
    fn test_lc_proof_verifier() {
        let lcp_receipt_bytes = include_bytes!("../../test_data/lcp_receipt.bin");
        let lcp_receipt: Receipt = borsh::from_slice(lcp_receipt_bytes).unwrap();

        let light_client_proof: LightClientProof = LightClientProof {
            lc_journal: lcp_receipt.journal.bytes.to_vec(),
        };

        let light_client_circuit_output: LightClientCircuitOutput =
            borsh::from_slice(light_client_proof.lc_journal.as_slice())
                .expect("Failed to deserialize light client circuit output");

        assert!(
            check_method_id(&light_client_circuit_output, REGTEST_LC_IMAGE_ID),
            "Light client proof method ID does not match the expected LC image ID"
        );

        println!("LCP Receipt: {:?}", lcp_receipt.clone());

        lcp_receipt.verify(REGTEST_LC_IMAGE_ID).unwrap();

        let light_client_proof: LightClientProof = LightClientProof {
            lc_journal: lcp_receipt.journal.bytes.to_vec(),
        };

        let light_client_circuit_output: LightClientCircuitOutput =
            borsh::from_slice(light_client_proof.lc_journal.as_slice())
                .expect("Failed to deserialize light client circuit output");

        assert!(
            check_method_id(&light_client_circuit_output, REGTEST_LC_IMAGE_ID),
            "Light client proof method ID does not match the expected LC image ID"
        );

        let expected_state_root =
            "8b1e363db80a6c20eb1a31db96d185eb7d5bb4f1e0ef458eb6ae288d58139ca5";
        let expected_last_block_hash =
            "6d378db6ada554cb29e67826a320be79bdd3f2138447c24302d6b31dd8951552";

        assert_eq!(
            hex::encode(light_client_circuit_output.l2_state_root),
            expected_state_root
        );
        assert_eq!(
            hex::encode(light_client_circuit_output.latest_da_state.block_hash),
            expected_last_block_hash
        );
    }
}
