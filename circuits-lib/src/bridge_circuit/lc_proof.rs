use crate::bridge_circuit_core::structs::LightClientProof;
use risc0_zkvm::guest::env;



const LC_IMAGE_ID: [u8; 32] = hex_literal::hex!("f9b82dad0590a31c4d58345a8d9f3865857d00b50ada1cd0234ff9bb781e36b0");

pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> [u8; 32] {
    env::verify(
        LC_IMAGE_ID,
        &light_client_proof.lc_journal
    ).unwrap();

    println!("Light client proof verified!");

    if light_client_proof.lc_journal.len() < 32 {
        panic!("Invalid light client journal");
    }

    light_client_proof.lc_journal[0..32].try_into().unwrap() // state root
}

    