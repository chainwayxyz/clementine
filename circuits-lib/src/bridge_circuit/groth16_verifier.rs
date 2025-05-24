use ark_bn254::{Bn254, Fr};
use ark_groth16::PreparedVerifyingKey;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;

use crate::common::utils::to_decimal;

use super::constants::{
    A0_ARK, A1_ARK, ASSUMPTIONS, BN_254_CONTROL_ID_ARK, CLAIM_TAG, INPUT, OUTPUT_TAG, POST_STATE,
    PREPARED_VK,
};
use super::groth16::CircuitGroth16Proof;
use super::structs::WorkOnlyCircuitOutput;
use hex::ToHex;
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub fn create_journal_digest(work_only_circuit_output: &WorkOnlyCircuitOutput) -> [u8; 32] {
    let pre_digest = borsh::to_vec(work_only_circuit_output).unwrap();
    Sha256::digest(pre_digest).into()
}

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
    .expect("slice has correct length");

    Sha256::digest(output_pre_digest).into()
}

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
    ) -> CircuitGroth16WithTotalWork {
        CircuitGroth16WithTotalWork {
            groth16_seal,
            total_work,
            genesis_state_hash,
        }
    }

    pub fn verify(&self, pre_state: &[u8; 32]) -> bool {
        let ark_proof: Proof<Bn254> = self.groth16_seal.into();
        let prepared_vk: PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
            CanonicalDeserialize::deserialize_uncompressed(PREPARED_VK).unwrap();

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
