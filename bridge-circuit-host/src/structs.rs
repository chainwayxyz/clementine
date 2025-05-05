use ark_bn254::Bn254;
use ark_ff::PrimeField;
use bitcoin::{Network, Transaction, Txid, XOnlyPublicKey};
use circuits_lib::common::constants::{FIRST_FIVE_OUTPUTS, NUMBER_OF_ASSERT_TXS};
use circuits_lib::{
    bridge_circuit::{
        spv::SPV,
        structs::{LightClientProof, StorageProof, WatchtowerInput},
    },
    header_chain::BlockHeaderCircuitOutput,
};
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

use crate::utils::get_ark_verifying_key;

#[derive(Debug, Clone)]
pub struct BridgeCircuitHostParams {
    pub kickoff_tx_id: Txid,
    pub spv: SPV,
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
    pub headerchain_receipt: Receipt,
    pub light_client_proof: LightClientProof,
    pub lcp_receipt: Receipt,
    pub storage_proof: StorageProof,
    pub network: Network,
    pub watchtower_inputs: Vec<WatchtowerInput>,
    pub all_tweaked_watchtower_pubkeys: Vec<XOnlyPublicKey>,
}

#[derive(Debug, Clone)]
pub enum BridgeCircuitHostParamsError {
    InvalidKickoffTx,
    InvalidHeaderchainReceipt,
    InvalidLightClientProof,
    InvalidLcpReceipt,
    InvalidStorageProof,
    InvalidNetwork,
    InvalidWatchtowerInputs,
    InvalidPubkey,
    InvalidNumberOfKickoffOutputs,
}

impl BridgeCircuitHostParams {
    const OP_RETURN_OUTPUT: usize = 1;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kickoff_tx_id: Txid,
        spv: SPV,
        block_header_circuit_output: BlockHeaderCircuitOutput,
        headerchain_receipt: Receipt,
        light_client_proof: LightClientProof,
        lcp_receipt: Receipt,
        storage_proof: StorageProof,
        network: Network,
        watchtower_inputs: Vec<WatchtowerInput>,
        all_tweaked_watchtower_pubkeys: Vec<XOnlyPublicKey>,
    ) -> Self {
        BridgeCircuitHostParams {
            kickoff_tx_id,
            spv,
            block_header_circuit_output,
            headerchain_receipt,
            light_client_proof,
            lcp_receipt,
            storage_proof,
            network,
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_wt_tx(
        kickoff_tx: Transaction,
        spv: SPV,
        headerchain_receipt: Receipt,
        light_client_proof: LightClientProof,
        lcp_receipt: Receipt,
        storage_proof: StorageProof,
        network: Network,
        watchtower_contexts: &[WatchtowerContext],
    ) -> Result<Self, BridgeCircuitHostParamsError> {
        let watchtower_inputs =
            Self::get_wt_inputs(kickoff_tx.compute_txid(), watchtower_contexts)?;

        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::from_slice(&headerchain_receipt.journal.bytes)
                .map_err(|_| BridgeCircuitHostParamsError::InvalidHeaderchainReceipt)?;

        let all_tweaked_watchtower_pubkeys = Self::get_all_pubkeys(&kickoff_tx)?;

        Ok(BridgeCircuitHostParams {
            kickoff_tx_id: kickoff_tx.compute_txid(),
            spv,
            block_header_circuit_output,
            headerchain_receipt,
            light_client_proof,
            lcp_receipt,
            storage_proof,
            network,
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
        })
    }

    fn get_wt_inputs(
        kickoff_tx_id: Txid,
        watchtower_contexts: &[WatchtowerContext],
    ) -> Result<Vec<WatchtowerInput>, BridgeCircuitHostParamsError> {
        watchtower_contexts
            .iter()
            .map(|context| {
                WatchtowerInput::from_txs(
                    kickoff_tx_id,
                    context.watchtower_tx.clone(),
                    context.previous_txs,
                )
                .map_err(|_| BridgeCircuitHostParamsError::InvalidWatchtowerInputs)
            })
            .collect()
    }

    fn get_all_pubkeys(
        kickoff_tx: &Transaction,
    ) -> Result<Vec<XOnlyPublicKey>, BridgeCircuitHostParamsError> {
        let start_index = FIRST_FIVE_OUTPUTS + NUMBER_OF_ASSERT_TXS;
        let end_index = kickoff_tx
            .output
            .len()
            .checked_sub(Self::OP_RETURN_OUTPUT)
            .ok_or(BridgeCircuitHostParamsError::InvalidNumberOfKickoffOutputs)?;

        let mut all_tweaked_watchtower_pubkeys = Vec::new();

        for i in (start_index..end_index).step_by(2) {
            let output = &kickoff_tx.output[i];

            let xonly_public_key =
                XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..34])
                    .map_err(|_| BridgeCircuitHostParamsError::InvalidPubkey)?;

            all_tweaked_watchtower_pubkeys.push(xonly_public_key);
        }
        Ok(all_tweaked_watchtower_pubkeys)
    }
}

pub struct WatchtowerContext<'a> {
    pub watchtower_tx: Transaction,
    pub previous_txs: &'a [Transaction],
}

#[derive(Debug, Clone, Copy)]
pub struct SuccinctBridgeCircuitPublicInputs {
    pub kickoff_txid: [u8; 32],
    pub payout_tx_block_hash: [u8; 20],
    pub latest_block_hash: [u8; 20],
    pub challenge_sending_watchtowers: [u8; 20],
    pub move_to_vault_txid: [u8; 32],
    pub watchtower_pubkeys_digest: [u8; 32],
    pub operator_id: [u8; 32],
}

impl SuccinctBridgeCircuitPublicInputs {
    pub fn journal_hash(self) -> blake3::Hash {
        let pre_deposit_constant = [
            self.kickoff_txid,
            self.move_to_vault_txid,
            self.watchtower_pubkeys_digest,
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
            self.kickoff_txid,
            self.move_to_vault_txid,
            self.watchtower_pubkeys_digest,
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
