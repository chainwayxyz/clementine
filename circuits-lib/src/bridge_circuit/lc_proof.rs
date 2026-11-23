//! # Light Client Proof Verifier
//! This module implements the light client proof verifier for the bridge circuit.
//! It includes functions to verify light client proofs and extracting the light client circuit output.

use super::structs::LightClientProof;
use crate::common::{programs::CURRENT_LIGHT_CLIENT, zkvm::ZkvmGuest};
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;

/// Deserializes the light client circuit output from journal bytes.
fn deserialize_circuit_output(journal: &[u8]) -> LightClientCircuitOutput {
    borsh::from_slice(journal).expect("Failed to deserialize light client circuit output")
}

/// Verifies the light client proof and returns the light client circuit output.
///
/// Citrea's light client proof is a compressed SP1 proof, verified with native recursion, or
/// a mock receipt off mainnet, which is not verified.
pub fn lc_proof_verifier(
    guest: &impl ZkvmGuest,
    light_client_proof: LightClientProof,
) -> LightClientCircuitOutput {
    let light_client_circuit_output = deserialize_circuit_output(&light_client_proof.lc_journal);

    if light_client_proof.verification_mode.should_verify() {
        guest.verify(CURRENT_LIGHT_CLIENT.recursion, &light_client_circuit_output);
    }

    assert_eq!(
        light_client_circuit_output.light_client_proof_method_id, CURRENT_LIGHT_CLIENT.recursion,
        "Light client proof method ID does not match the expected light client program key"
    );

    light_client_circuit_output
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::common::{
        programs::REGTEST, sp1::Receipt, verification_mode::GuestVerificationMode,
    };

    #[test]
    fn test_lc_proof_verifier() {
        let lcp_receipt_bytes = include_bytes!("../../test_data/lcp_receipt.bin");
        let lcp_receipt: Receipt = borsh::from_slice(lcp_receipt_bytes).unwrap();

        let light_client_proof = LightClientProof::from_receipt(&lcp_receipt);

        let light_client_circuit_output: LightClientCircuitOutput =
            borsh::from_slice(light_client_proof.lc_journal.as_slice())
                .expect("Failed to deserialize light client circuit output");

        assert_eq!(
            light_client_circuit_output.light_client_proof_method_id,
            REGTEST.light_client.recursion
        );

        println!("LCP Receipt: {:?}", lcp_receipt.clone());

        assert_eq!(
            light_client_proof.verification_mode,
            GuestVerificationMode::SkipForTesting
        );

        // The guest verifies the proof of the re-encoded output, which must be the journal.
        assert_eq!(
            borsh::to_vec(&light_client_circuit_output).unwrap(),
            light_client_proof.lc_journal
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
