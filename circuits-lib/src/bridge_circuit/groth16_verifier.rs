//! Verification of an SP1 work-only proof reconstructed from a watchtower challenge.
use super::{groth16::CircuitGroth16Proof, structs::WorkOnlyCircuitOutput};

pub struct CircuitGroth16WithTotalWork {
    groth16_seal: CircuitGroth16Proof,
    total_work: [u8; 16],
    genesis_state_hash: [u8; 32],
}
impl CircuitGroth16WithTotalWork {
    pub fn new(
        groth16_seal: CircuitGroth16Proof,
        total_work: [u8; 16],
        genesis_state_hash: [u8; 32],
    ) -> Self {
        Self {
            groth16_seal,
            total_work,
            genesis_state_hash,
        }
    }
    pub fn verify(&self, program: &[u8; 32]) -> bool {
        let output = WorkOnlyCircuitOutput {
            work_u128: self.total_work,
            genesis_state_hash: self.genesis_state_hash,
        };
        let public_values = borsh::to_vec(&output).expect("work output serialization");
        #[cfg(not(feature = "use-test-vk"))]
        {
            if crate::common::sp1::groth16::scalar_from_bytes(program).is_err() {
                return false;
            }
            // The bridge guest uses SP1's BN254 precompiles. Bitcoin's verifier
            // still uses the program-specialized key with one variable input.
            sp1_verifier::Groth16Verifier::verify_gnark_proof(
                &self.groth16_seal.to_gnark_bytes(),
                &[
                    *program,
                    sp1_verifier::hash_public_inputs(&public_values),
                    [0; 32],
                    *sp1_verifier::VK_ROOT_BYTES,
                    [0; 32],
                ],
                &sp1_verifier::GROTH16_VK_BYTES,
            )
            .is_ok()
        }
        #[cfg(feature = "use-test-vk")]
        {
            crate::common::sp1::groth16::development::verify(
                program,
                self.groth16_seal.into(),
                crate::common::sp1::groth16::public_input(&public_values),
            )
        }
    }
}
