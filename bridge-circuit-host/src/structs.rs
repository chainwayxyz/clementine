use circuits_lib::bridge_circuit_core::{
    structs::{LightClientProof, StorageProof},
    winternitz::WinternitzHandler,
};
use final_spv::spv::SPV;
use header_chain::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

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
}
