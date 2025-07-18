use ark_bn254::{Bn254, Fr};
use ark_groth16::PreparedVerifyingKey;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;
use num_traits::Num;

use super::constants::{
    get_prepared_vk, A0_ARK, A1_ARK, ASSUMPTIONS, BN_254_CONTROL_ID_ARK, CLAIM_TAG, INPUT,
    OUTPUT_TAG, POST_STATE,
};
use super::groth16::CircuitGroth16Proof;
use super::structs::WorkOnlyCircuitOutput;
use hex::ToHex;
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// Creates a digest for the journal of the work-only circuit output.
pub fn create_journal_digest(work_only_circuit_output: &WorkOnlyCircuitOutput) -> [u8; 32] {
    let pre_digest = borsh::to_vec(work_only_circuit_output).unwrap();
    Sha256::digest(pre_digest).into()
}

/// Creates an output digest for the work-only circuit output.
pub fn create_output_digest(work_only_circuit_output: &WorkOnlyCircuitOutput) -> [u8; 32] {
    let journal_digest: [u8; 32] = create_journal_digest(work_only_circuit_output);
    let len_output: u16 = 2;

    let output_pre_digest: [u8; 98] = [
        &OUTPUT_TAG,
        &journal_digest[..],
        &ASSUMPTIONS[..],
        &len_output.to_le_bytes(),
    ]
    .concat()
    .try_into()
    .expect("Slice has correct length");

    Sha256::digest(output_pre_digest).into()
}

/// Creates a claim digest for the work-only circuit output.
pub fn create_claim_digest(output_digest: &[u8; 32], pre_state: &[u8; 32]) -> [u8; 32] {
    let data: [u8; 8] = [0; 8];

    let claim_len: u16 = 4;

    let concatenated = [
        &CLAIM_TAG,
        &INPUT,
        pre_state,
        &POST_STATE,
        output_digest,
        &data[..],
        &claim_len.to_le_bytes(),
    ]
    .concat();

    let mut claim_digest = Sha256::digest(concatenated);
    claim_digest.reverse();

    claim_digest.into()
}

/// Groth16 proof with total work and genesis state hash. In Clementine, this is provided by
/// the watchtowers who challenge the operator whom they suspect of malicious behavior. Just
/// by knowing the Groth16 proof and the total work, we can reconstruct the public outputs of
/// the proof and verify it against the Verifying Key (VK) of the Groth16 proof.
pub struct CircuitGroth16WithTotalWork {
    groth16_seal: CircuitGroth16Proof,
    total_work: [u8; 16],
    genesis_state_hash: [u8; 32],
}

impl CircuitGroth16WithTotalWork {
    /// Creates a new instance of `CircuitGroth16WithTotalWork`.
    pub fn new(
        groth16_seal: CircuitGroth16Proof,
        total_work: [u8; 16],
        genesis_state_hash: [u8; 32],
    ) -> CircuitGroth16WithTotalWork {
        CircuitGroth16WithTotalWork {
            groth16_seal,
            total_work,
            genesis_state_hash,
        }
    }

    /// Given the `pre_state` (which is actually the `method ID` of the work-only circuit),
    /// verifies the Groth16 proof against the prepared Verifying Key (VK) and the public inputs.
    pub fn verify(&self, pre_state: &[u8; 32]) -> bool {
        let ark_proof: Proof<Bn254> = self.groth16_seal.into();

        let prepared_vk: &[u8] = get_prepared_vk();

        let prepared_vk: PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
            CanonicalDeserialize::deserialize_uncompressed(prepared_vk).unwrap();

        let output_digest = create_output_digest(&WorkOnlyCircuitOutput {
            work_u128: self.total_work,
            genesis_state_hash: self.genesis_state_hash,
        });

        let claim_digest: [u8; 32] = create_claim_digest(&output_digest, pre_state);

        let claim_digest_hex: String = claim_digest.encode_hex();
        let c0_str = &claim_digest_hex[32..64];
        let c1_str = &claim_digest_hex[0..32];

        let c0_dec = to_decimal(c0_str).unwrap();
        let c1_dec = to_decimal(c1_str).unwrap();

        let c0 = Fr::from_str(&c0_dec).unwrap();
        let c1 = Fr::from_str(&c1_dec).unwrap();

        let public_inputs = vec![A0_ARK, A1_ARK, c0, c1, BN_254_CONTROL_ID_ARK];

        ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs)
            .unwrap()
    }
}

/// Converts a hexadecimal string to a decimal string representation.
pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_decimal() {
        assert_eq!(to_decimal("0"), Some("0".to_string()));
        assert_eq!(to_decimal("1"), Some("1".to_string()));
        assert_eq!(to_decimal("a"), Some("10".to_string()));
        assert_eq!(to_decimal("f"), Some("15".to_string()));
        assert_eq!(to_decimal("10"), Some("16".to_string()));
        assert_eq!(to_decimal("1f"), Some("31".to_string()));
        assert_eq!(to_decimal("100"), Some("256".to_string()));
        assert_eq!(to_decimal("1ff"), Some("511".to_string()));
        assert_eq!(to_decimal("citrea"), None);
    }
}
