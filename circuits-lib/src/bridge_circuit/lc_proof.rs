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

#[inline]
fn is_regtest() -> bool {
    option_env!("BITCOIN_NETWORK") == Some("regtest")
}

/// Deserializes the light client circuit output from journal bytes.
fn deserialize_circuit_output(journal: &[u8]) -> LightClientCircuitOutput {
    borsh::from_slice(journal).expect("Failed to deserialize light client circuit output")
}

/// Verifies the light client proof and returns the light client circuit output.
pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> LightClientCircuitOutput {
    if !is_regtest() {
        env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal)
            .expect("Failed to verify light client proof");
    }

    let light_client_circuit_output = deserialize_circuit_output(&light_client_proof.lc_journal);

    if !is_regtest() {
        assert!(
            check_method_id(&light_client_circuit_output, LC_IMAGE_ID),
            "Light client proof method ID does not match the expected LC image ID"
        );
    }

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
            "87f4f2b4660485ea3ca667033a7fbd077a627946f0b444da101c6cc23a438382";
        let expected_last_block_hash =
            "363fd37d55e728d7292f495768540fb7454770a142fe8b44033d836cb0e15d37";

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
