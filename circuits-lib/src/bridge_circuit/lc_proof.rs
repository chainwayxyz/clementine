use super::structs::LightClientProof;
// use risc0_zkvm::guest::env;

// const LC_IMAGE_ID: [u8; 32] =
//     hex_literal::hex!("f0cca5b444bd9980d81bd8726c6b34e6f5da613174b5794957b1870288bdd595");

pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> [u8; 32] {
    // env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal).unwrap();

    if light_client_proof.lc_journal.len() < 32 {
        panic!("Invalid light client journal");
    }

    light_client_proof.lc_journal[0..32].try_into().unwrap() // state root
}
