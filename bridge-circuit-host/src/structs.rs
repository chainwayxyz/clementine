use alloy_rpc_types::EIP1186StorageProof;
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use bitcoin::{hashes::Hash, Network, Transaction, Txid, XOnlyPublicKey};
use circuits_lib::{
    bridge_circuit::{
        deposit_constant, journal_hash, parse_op_return_data,
        spv::SPV,
        structs::{
            BridgeCircuitInput, ChallengeSendingWatchtowers, DepositConstant, LatestBlockhash,
            LightClientProof, PayoutTxBlockhash, StorageProof, WatchtowerInput,
        },
        verify_watchtower_challenges,
    },
    header_chain::BlockHeaderCircuitOutput,
};
use risc0_zkvm::Receipt;

use crate::utils::get_ark_verifying_key;
use thiserror::Error;

const OP_RETURN_OUTPUT: usize = 1;
const ANCHOR_OUTPUT: usize = 1;

#[derive(Debug, Clone)]
pub struct BridgeCircuitHostParams {
    pub kickoff_tx: Transaction,
    pub spv: SPV,
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
    pub headerchain_receipt: Receipt,
    pub light_client_proof: LightClientProof,
    pub lcp_receipt: Receipt,
    pub storage_proof: StorageProof,
    pub network: Network,
    pub watchtower_inputs: Vec<WatchtowerInput>,
    pub all_tweaked_watchtower_pubkeys: Vec<XOnlyPublicKey>,
    pub watchtower_challenge_connector_start_idx: u16,
    pub payout_input_index: u16,
}

#[derive(Debug, Clone, Error)]
pub enum BridgeCircuitHostParamsError {
    #[error("Invalid kickoff transaction")]
    InvalidKickoffTx,
    #[error("Invalid headerchain receipt")]
    InvalidHeaderchainReceipt,
    #[error("Invalid light client proof")]
    InvalidLightClientProof,
    #[error("Invalid LCP receipt")]
    InvalidLcpReceipt,
    #[error("Invalid storage proof")]
    InvalidStorageProof,
    #[error("Invalid network")]
    InvalidNetwork,
    #[error("Invalid watchtower inputs")]
    InvalidWatchtowerInputs,
    #[error("Invalid public key")]
    InvalidPubkey,
    #[error("Invalid number of kickoff outputs")]
    InvalidNumberOfKickoffOutputs,
    #[error("Payout input index not found")]
    PayoutInputIndexNotFound,
    #[error("Payout input index too large: {0}")]
    PayoutInputIndexTooLarge(usize),
    #[error("Invalid kickoff transaction vout")]
    KickOffTxInvalidVout,
}

impl BridgeCircuitHostParams {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kickoff_tx: Transaction,
        spv: SPV,
        block_header_circuit_output: BlockHeaderCircuitOutput,
        headerchain_receipt: Receipt,
        light_client_proof: LightClientProof,
        lcp_receipt: Receipt,
        storage_proof: StorageProof,
        network: Network,
        watchtower_inputs: Vec<WatchtowerInput>,
        all_tweaked_watchtower_pubkeys: Vec<XOnlyPublicKey>,
        watchtower_challenge_connector_start_idx: u16,
        payout_input_index: u16,
    ) -> Self {
        BridgeCircuitHostParams {
            kickoff_tx,
            spv,
            block_header_circuit_output,
            headerchain_receipt,
            light_client_proof,
            lcp_receipt,
            storage_proof,
            network,
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
            watchtower_challenge_connector_start_idx,
            payout_input_index,
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
        watchtower_challenge_connector_start_idx: u16,
    ) -> Result<Self, BridgeCircuitHostParamsError> {
        let watchtower_inputs = get_wt_inputs(
            kickoff_tx.compute_txid(),
            watchtower_contexts,
            watchtower_challenge_connector_start_idx,
        )?;

        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::from_slice(&headerchain_receipt.journal.bytes)
                .map_err(|_| BridgeCircuitHostParamsError::InvalidHeaderchainReceipt)?;

        let all_tweaked_watchtower_pubkeys =
            get_all_pubkeys(&kickoff_tx, watchtower_challenge_connector_start_idx)?;

        let storage_proof_utxo: EIP1186StorageProof =
            serde_json::from_str(&storage_proof.storage_proof_utxo)
                .expect("Failed to deserialize UTXO storage proof");

        let wd_txid_bytes: [u8; 32] = storage_proof_utxo.value.to_be_bytes();

        let wd_txid: Txid = bitcoin::consensus::deserialize(&wd_txid_bytes)
            .map_err(|_| BridgeCircuitHostParamsError::InvalidStorageProof)?;

        let payout_input_index = get_payout_input_index(wd_txid, &spv.transaction.0)?;

        Ok(BridgeCircuitHostParams {
            kickoff_tx,
            spv,
            block_header_circuit_output,
            headerchain_receipt,
            light_client_proof,
            lcp_receipt,
            storage_proof,
            network,
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
            watchtower_challenge_connector_start_idx,
            payout_input_index,
        })
    }

    pub fn into_bridge_circuit_input(self) -> BridgeCircuitInput {
        let BridgeCircuitHostParams {
            kickoff_tx,
            spv,
            block_header_circuit_output,
            headerchain_receipt: _,
            light_client_proof,
            lcp_receipt: _,
            storage_proof,
            network: _,
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
            watchtower_challenge_connector_start_idx,
            payout_input_index,
        } = self;

        let all_tweaked_watchtower_pubkeys: Vec<[u8; 32]> = all_tweaked_watchtower_pubkeys
            .iter()
            .map(|pubkey| pubkey.serialize())
            .collect();

        BridgeCircuitInput::new(
            kickoff_tx,
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
            block_header_circuit_output,
            spv,
            payout_input_index,
            light_client_proof,
            storage_proof,
            watchtower_challenge_connector_start_idx,
        )
    }
}

fn get_payout_input_index(
    wd_txid: Txid,
    payout_tx: &Transaction,
) -> Result<u16, BridgeCircuitHostParamsError> {
    for (index, input) in payout_tx.input.iter().enumerate() {
        if input.previous_output.txid == wd_txid {
            return u16::try_from(index).map_err(|_| {
                // This should never happen
                BridgeCircuitHostParamsError::PayoutInputIndexTooLarge(index)
            });
        }
    }
    Err(BridgeCircuitHostParamsError::PayoutInputIndexNotFound)
}

fn get_wt_inputs(
    kickoff_tx_id: Txid,
    watchtower_contexts: &[WatchtowerContext],
    watchtower_challenge_connector_start_idx: u16,
) -> Result<Vec<WatchtowerInput>, BridgeCircuitHostParamsError> {
    watchtower_contexts
        .iter()
        .map(|context| {
            WatchtowerInput::from_txs(
                kickoff_tx_id,
                context.watchtower_tx.clone(),
                &context.prevout_txs,
                watchtower_challenge_connector_start_idx,
            )
            .map_err(|_| BridgeCircuitHostParamsError::InvalidWatchtowerInputs)
        })
        .collect()
}

pub fn get_all_pubkeys(
    kickoff_tx: &Transaction,
    watchtower_challenge_connector_start_idx: u16,
) -> Result<Vec<XOnlyPublicKey>, BridgeCircuitHostParamsError> {
    let start_index = watchtower_challenge_connector_start_idx as usize;
    let end_index = kickoff_tx
        .output
        .len()
        .checked_sub(OP_RETURN_OUTPUT)
        .ok_or(BridgeCircuitHostParamsError::InvalidNumberOfKickoffOutputs)?
        .checked_sub(ANCHOR_OUTPUT)
        .ok_or(BridgeCircuitHostParamsError::InvalidNumberOfKickoffOutputs)?;

    let mut all_tweaked_watchtower_pubkeys = Vec::new();

    for i in (start_index..end_index).step_by(2) {
        let output = &kickoff_tx.output[i];

        if !output.script_pubkey.is_p2tr() {
            return Err(BridgeCircuitHostParamsError::InvalidPubkey);
        }

        let xonly_public_key = XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..34])
            .map_err(|_| BridgeCircuitHostParamsError::InvalidPubkey)?;

        all_tweaked_watchtower_pubkeys.push(xonly_public_key);
    }
    Ok(all_tweaked_watchtower_pubkeys)
}

pub struct WatchtowerContext {
    pub watchtower_tx: Transaction,
    pub prevout_txs: Vec<Transaction>,
}

#[derive(Debug, Clone)]
pub struct SuccinctBridgeCircuitPublicInputs {
    pub bridge_circuit_input: BridgeCircuitInput,
    pub challenge_sending_watchtowers: ChallengeSendingWatchtowers,
    pub deposit_constant: DepositConstant,
    pub payout_tx_block_hash: PayoutTxBlockhash,
    pub latest_block_hash: LatestBlockhash,
}

impl SuccinctBridgeCircuitPublicInputs {
    pub fn new(bridge_circuit_input: BridgeCircuitInput) -> Self {
        let latest_block_hash: LatestBlockhash =
            bridge_circuit_input.hcp.chain_state.best_block_hash[12..32]
                .try_into()
                .unwrap();
        let payout_tx_block_hash: PayoutTxBlockhash = bridge_circuit_input
            .payout_spv
            .block_header
            .compute_block_hash()[12..32]
            .try_into()
            .unwrap();

        let deposit_constant = host_deposit_constant(&bridge_circuit_input);
        let watchtower_challenge_set = verify_watchtower_challenges(&bridge_circuit_input);

        Self {
            bridge_circuit_input,
            challenge_sending_watchtowers: ChallengeSendingWatchtowers(
                watchtower_challenge_set.challenge_senders,
            ),
            deposit_constant,
            payout_tx_block_hash,
            latest_block_hash,
        }
    }

    pub fn host_journal_hash(&self) -> blake3::Hash {
        journal_hash(
            self.payout_tx_block_hash,
            self.latest_block_hash,
            self.challenge_sending_watchtowers,
            self.deposit_constant,
        )
    }
}

fn host_deposit_constant(input: &BridgeCircuitInput) -> DepositConstant {
    // operator_id
    let last_output = input.payout_spv.transaction.output.last().unwrap();

    let deposit_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&input.sp.storage_proof_deposit_txid)
            .expect("Failed to deserialize deposit storage proof");

    let round_txid = input.kickoff_tx.input[0]
        .previous_output
        .txid
        .to_byte_array();

    if input.kickoff_tx.input[0]
        .previous_output
        .txid
        .to_byte_array()
        != round_txid
    {
        panic!("Kickoff transaction input does not match the expected round txid");
    }

    let kickff_round_vout = input.kickoff_tx.input[0].previous_output.vout;

    let operator_xonlypk: [u8; 32] = parse_op_return_data(&last_output.script_pubkey)
        .expect("Failed to get operator xonlypk")
        .try_into()
        .expect("Invalid operator xonlypk");

    let deposit_value_bytes: [u8; 32] = deposit_storage_proof.value.to_be_bytes::<32>();

    deposit_constant(
        operator_xonlypk,
        input.watchtower_challenge_connector_start_idx,
        &input.all_tweaked_watchtower_pubkeys,
        deposit_value_bytes,
        round_txid,
        kickff_round_vout,
        input.hcp.genesis_state_hash,
    )
}

// Convert to unit type all fields of the struct
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
