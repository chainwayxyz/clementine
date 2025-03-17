use ark_bn254::Bn254;
use ark_ff::PrimeField;
use circuits_lib::bridge_circuit::{
    structs::{LightClientProof, StorageProof},
    winternitz::WinternitzHandler,
};
use final_spv::spv::SPV;
use header_chain::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

use crate::utils::get_ark_verifying_key;

#[derive(Debug, Clone)]
pub struct BridgeCircuitHostParams {
    pub winternitz_details: Vec<WinternitzHandler>,
    pub spv: SPV,
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
    pub headerchain_receipt: Receipt,
    pub light_client_proof: LightClientProof,
    pub lcp_receipt: Receipt,
    pub storage_proof: StorageProof,
    pub num_of_watchtowers: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SuccinctBridgeCircuitPublicInputs {
    pub payout_tx_block_hash: [u8; 20],
    pub latest_block_hash: [u8; 20],
    pub challenge_sending_watchtowers: [u8; 20],
    pub move_to_vault_txid: [u8; 32],
    pub watcthower_challenge_wpks_hash: [u8; 32],
    pub operator_id: [u8; 32],
}

impl SuccinctBridgeCircuitPublicInputs {
    pub fn journal_hash(self) -> blake3::Hash {
        let pre_deposit_constant = [
            self.move_to_vault_txid,
            self.watcthower_challenge_wpks_hash,
            self.operator_id,
        ]
        .concat();

        let deposit_constant: [u8; 32] = Sha256::digest(&pre_deposit_constant).into();

        let concatenated_data = [
            self.payout_tx_block_hash,
            self.latest_block_hash,
            self.challenge_sending_watchtowers,
        ]
        .concat();
        let binding = blake3::hash(&concatenated_data);
        let hash_bytes = binding.as_bytes();

        let concat_journal = [deposit_constant, *hash_bytes].concat();

        blake3::hash(&concat_journal)
    }

    pub fn deposit_constant(self) -> [u8; 32] {
        let pre_deposit_constant = [
            self.move_to_vault_txid,
            self.watcthower_challenge_wpks_hash,
            self.operator_id,
        ]
        .concat();
        Sha256::digest(&pre_deposit_constant).into()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BridgeCircuitBitvmInputs {
    pub payout_tx_block_hash: [u8; 20],
    pub latest_block_hash: [u8; 20],
    pub challenge_sending_watchtowers: [u8; 20],
    pub deposit_constant: [u8; 32],
    pub combined_method_id: [u8; 32],
}

impl BridgeCircuitBitvmInputs {
    pub fn new(
        payout_tx_block_hash: [u8; 20],
        latest_block_hash: [u8; 20],
        challenge_sending_watchtowers: [u8; 20],
        deposit_constant: [u8; 32],
        combined_method_id: [u8; 32],
    ) -> Self {
        Self {
            payout_tx_block_hash,
            latest_block_hash,
            challenge_sending_watchtowers,
            deposit_constant,
            combined_method_id,
        }
    }

    pub fn calculate_groth16_public_input(&self) -> blake3::Hash {
        let concatenated_data = [
            self.payout_tx_block_hash,
            self.latest_block_hash,
            self.challenge_sending_watchtowers,
        ]
        .concat();
        let x = blake3::hash(&concatenated_data);
        let hash_bytes = x.as_bytes();

        let concat_journal = [self.deposit_constant, *hash_bytes].concat();

        let journal_hash = blake3::hash(&concat_journal);

        let hash_bytes = journal_hash.as_bytes();

        let concat_input = [self.combined_method_id, *hash_bytes].concat();

        blake3::hash(&concat_input)
    }

    pub fn verify_bridge_circuit(&self, proof: ark_groth16::Proof<Bn254>) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.payout_tx_block_hash);
        hasher.update(&self.latest_block_hash);
        hasher.update(&self.challenge_sending_watchtowers);
        let x = hasher.finalize();
        let x_bytes: [u8; 32] = x.into();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.deposit_constant);
        hasher.update(&x_bytes);
        let y = hasher.finalize();
        let y_bytes: [u8; 32] = y.into();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.combined_method_id);
        hasher.update(&y_bytes);
        let public_output = hasher.finalize();

        let public_output_bytes: [u8; 32] = public_output.into();
        let public_input_scalar =
            ark_bn254::Fr::from_be_bytes_mod_order(&public_output_bytes[0..31]);

        let ark_vk = get_ark_verifying_key();
        let ark_pvk = ark_groth16::prepare_verifying_key(&ark_vk);

        ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
            &ark_pvk,
            &proof,
            &[public_input_scalar],
        )
        .unwrap()
    }
}
