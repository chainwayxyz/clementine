use crate::bridge_circuit_core::groth16::CircuitGroth16Proof;
use crate::bridge_circuit_core::utils::to_decimal;
use ark_bn254::{Bn254, Fr};
use ark_groth16::PreparedVerifyingKey;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;
use risc0_zkvm::guest::env;

use super::constants::{
    A0_ARK, A1_ARK, ASSUMPTIONS, BN_254_CONTROL_ID_ARK, CLAIM_TAG, INPUT, OUTPUT_TAG, POST_STATE,
    PREPARED_VK,
};
use hex::ToHex;
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub fn create_output_digest(total_work: &[u8; 16]) -> [u8; 32] {
    let total_work_digest: [u8; 32] = Sha256::digest(total_work).into();
    let len_output: [u8; 2] = hex::decode("0200").unwrap().try_into().unwrap();

    let output_pre_digest: [u8; 98] = [
        &OUTPUT_TAG,
        &total_work_digest[..],
        &ASSUMPTIONS[..],
        &len_output[..],
    ]
    .concat()
    .try_into()
    .expect("slice has correct length");

    let res = Sha256::digest(output_pre_digest).into();
    println!("Output digest: {:?}", res);
    let hex_res = hex::encode(res);
    println!("Hex output digest: {}", hex_res);
    res
}

pub fn create_claim_digest(output_digest: &[u8; 32], pre_state: &[u8; 32]) -> [u8; 32] {
    let data: [u8; 8] = [0; 8];

    let claim_len: [u8; 2] = [4, 0];

    let concatenated = [
        &CLAIM_TAG,
        &INPUT,
        pre_state,
        &POST_STATE,
        output_digest,
        &data[..],
        &claim_len,
    ]
    .concat();

    let mut claim_digest = Sha256::digest(concatenated);
    claim_digest.reverse();

    let res = claim_digest.into();
    println!("Claim digest: {:?}", res);
    let hex_res = hex::encode(res);
    println!("Hex claim digest: {}", hex_res);
    res
}
pub struct CircuitGroth16WithTotalWork {
    groth16_seal: CircuitGroth16Proof,
    total_work: [u8; 16],
}

impl CircuitGroth16WithTotalWork {
    pub fn new(
        groth16_seal: CircuitGroth16Proof,
        total_work: [u8; 16],
    ) -> CircuitGroth16WithTotalWork {
        CircuitGroth16WithTotalWork {
            groth16_seal,
            total_work,
        }
    }

    pub fn verify(&self, pre_state: &[u8; 32]) -> bool {
        println!("Verifying Groth16 proof");
        println!("Pre-state: {:?}", pre_state);
        let hex_pre_state = hex::encode(pre_state);
        println!("Hex pre-state: {}", hex_pre_state);
        let ark_proof: Proof<Bn254> = self.groth16_seal.into();
        let start = env::cycle_count();
        let prepared_vk: PreparedVerifyingKey<ark_ec::bn::Bn<ark_bn254::Config>> =
            CanonicalDeserialize::deserialize_uncompressed(PREPARED_VK).unwrap();
        let end = env::cycle_count();
        println!("PVK: {}", end - start);
        let start = env::cycle_count();

        let output_digest = create_output_digest(&self.total_work);

        let claim_digest: [u8; 32] = create_claim_digest(&output_digest, pre_state);

        let claim_digest_hex: String = claim_digest.encode_hex();
        let c0_str = &claim_digest_hex[32..64];
        let c1_str = &claim_digest_hex[0..32];

        let c0_dec = to_decimal(c0_str).unwrap();
        let c1_dec = to_decimal(c1_str).unwrap();

        let c0 = Fr::from_str(&c0_dec).unwrap();
        let c1 = Fr::from_str(&c1_dec).unwrap();

        let public_inputs = vec![A0_ARK, A1_ARK, c0, c1, BN_254_CONTROL_ID_ARK];

        let end = env::cycle_count();
        println!("PPI: {}", end - start);
        println!("Public inputs: {:?}", public_inputs);
        println!("Proof: {:?}", ark_proof);
        println!("Prepared VK: {:?}", prepared_vk);
        let res =
            ark_groth16::Groth16::<Bn254>::verify_proof(&prepared_vk, &ark_proof, &public_inputs)
                .unwrap();
        println!("Groth16 verification: {}", res);
        res
    }
}
