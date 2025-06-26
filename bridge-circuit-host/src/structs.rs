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
use eyre::Result;
use risc0_zkvm::Receipt;

use crate::utils::get_ark_verifying_key;
use thiserror::Error;

const OP_RETURN_OUTPUT: usize = 1;
const ANCHOR_OUTPUT: usize = 1;

/// Parameters required for bridge circuit proof generation.
///
/// This struct contains all the necessary inputs and proofs required to generate
/// a bridge circuit proof, including transactions, receipts, and cryptographic proofs.
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

/// Errors that can occur when constructing or validating bridge circuit host parameters.
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
    #[error("Failed to deserialize storage proof: {0}")]
    StorageProofDeserializationError(String),
    #[error("Failed to parse operator public key")]
    InvalidOperatorPubkey,
    #[error("Kickoff transaction missing outputs")]
    MissingKickoffOutputs,
    #[error("Invalid deposit storage proof")]
    InvalidDepositStorageProof,
    #[error("Round transaction ID mismatch")]
    RoundTxidMismatch,
    #[error("Failed to verify bridge circuit proof")]
    ProofVerificationFailed,
}

impl BridgeCircuitHostParams {
    /// Creates a new instance of BridgeCircuitHostParams.
    ///
    /// # Arguments
    ///
    /// * `kickoff_tx` - The kickoff transaction
    /// * `spv` - Simplified Payment Verification proof for the payout transaction
    /// * `block_header_circuit_output` - Output from the block header circuit
    /// * `headerchain_receipt` - Receipt from the header chain proof
    /// * `light_client_proof` - Light client proof for validation
    /// * `lcp_receipt` - Receipt from the light client proof
    /// * `storage_proof` - Storage proof from the blockchain (l2) state
    /// * `network` - Bitcoin network (mainnet, testnet, etc.)
    /// * `watchtower_inputs` - Inputs including details about watchtower challenge transactions
    /// * `all_tweaked_watchtower_pubkeys` - All tweaked watchtower public keys
    /// * `watchtower_challenge_connector_start_idx` - Starting index for watchtower challenge connectors on kickoff tx
    /// * `payout_input_index` - Index of the payout input in the transaction
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

    /// Creates a new instance of BridgeCircuitHostParams with watchtower transactions.
    ///
    /// This method automatically derives several parameters from the provided watchtower contexts
    /// and validates the inputs before construction.
    ///
    /// # Arguments
    ///
    /// * `kickoff_tx` - The kickoff transaction
    /// * `spv` - Simplified Payment Verification proof for the payout transaction
    /// * `headerchain_receipt` - Receipt from the header chain proof
    /// * `light_client_proof` - Light client proof for validation
    /// * `lcp_receipt` - Receipt from the light client proof
    /// * `storage_proof` - Storage proof from the blockchain (l2) state
    /// * `network` - Bitcoin network
    /// * `watchtower_contexts` - Contexts containing watchtower transactions and transactions that includes prevouts
    /// * `watchtower_challenge_connector_start_idx` - Starting index for watchtower challenge connectors on kickoff tx
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the constructed `BridgeCircuitHostParams` or an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Watchtower input generation fails
    /// - Header chain receipt journal deserialization fails
    /// - Public key extraction from kickoff transaction fails
    /// - Storage proof deserialization fails
    /// - Payout input index calculation fails
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
            serde_json::from_str(&storage_proof.storage_proof_utxo).map_err(|e| {
                BridgeCircuitHostParamsError::StorageProofDeserializationError(e.to_string())
            })?;

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

    /// Converts the host parameters into bridge circuit input format.
    ///
    /// This method transforms the host parameters into the format required by the bridge circuit,
    /// serializing public keys and organizing the data appropriately.
    ///
    /// # Returns
    ///
    /// Returns a `BridgeCircuitInput` containing all the necessary data for circuit execution.
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

/// Finds the index of the payout input in the payout transaction based on the withdrawal transaction ID.
///
/// # Arguments
///
/// * `wd_txid` - The withdrawal transaction ID to search for
/// * `payout_tx` - The payout transaction to search within
///
/// # Returns
///
/// Returns a `Result` containing the input index as `u16` or an error.
///
/// # Errors
///
/// This function will return an error if:
/// - The withdrawal transaction ID is not found in any input
/// - The input index is too large to fit in a `u16`
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

/// Generates watchtower inputs from watchtower contexts.
///
/// # Arguments
///
/// * `kickoff_tx_id` - The transaction ID of the kickoff transaction
/// * `watchtower_contexts` - Array of watchtower contexts containing transactions
/// * `watchtower_challenge_connector_start_idx` - Starting index for watchtower challenge connectors on kickoff tx
///
/// # Returns
///
/// Returns a `Result` containing a vector of `WatchtowerInput` or an error.
///
/// # Errors
///
/// This function will return an error if any watchtower input generation fails.
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

/// Extracts all tweaked watchtower public keys from a kickoff transaction.
///
/// # Arguments
///
/// * `kickoff_tx` - The kickoff transaction containing watchtower public keys in its outputs
/// * `watchtower_challenge_connector_start_idx` - Starting index for watchtower challenge connectors on kickoff tx
///
/// # Returns
///
/// Returns a `Result` containing a vector of `XOnlyPublicKey` or an error.
///
/// # Errors
///
/// This function will return an error if:
/// - The kickoff transaction has insufficient outputs
/// - Any public key extraction fails
/// - The transaction structure is invalid
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

        let xonly_public_key = XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..34])
            .map_err(|_| BridgeCircuitHostParamsError::InvalidPubkey)?;

        all_tweaked_watchtower_pubkeys.push(xonly_public_key);
    }
    Ok(all_tweaked_watchtower_pubkeys)
}

/// Context containing watchtower transaction and transactions that include prevouts.
pub struct WatchtowerContext {
    pub watchtower_tx: Transaction,
    pub prevout_txs: Vec<Transaction>,
}

/// Public inputs for the succinct bridge circuit.
///
/// This struct contains all the public inputs that are committed after hashing to in the bridge circuit proof,
/// including block hashes, watchtower challenges, and deposit constants.
#[derive(Debug, Clone)]
pub struct SuccinctBridgeCircuitPublicInputs {
    pub bridge_circuit_input: BridgeCircuitInput,
    pub challenge_sending_watchtowers: ChallengeSendingWatchtowers,
    pub deposit_constant: DepositConstant,
    pub payout_tx_block_hash: PayoutTxBlockhash,
    pub latest_block_hash: LatestBlockhash,
}

impl SuccinctBridgeCircuitPublicInputs {
    /// Creates new succinct bridge circuit public inputs from bridge circuit input.
    ///
    /// # Arguments
    ///
    /// * `bridge_circuit_input` - The bridge circuit input containing all necessary data
    ///
    /// # Returns
    ///
    /// Returns a new instance of `SuccinctBridgeCircuitPublicInputs`.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Block hash extraction fails
    /// - Deposit constant calculation fails
    /// - Watchtower challenge verification fails
    pub fn new(
        bridge_circuit_input: BridgeCircuitInput,
    ) -> Result<Self, BridgeCircuitHostParamsError> {
        let latest_block_hash: LatestBlockhash =
            bridge_circuit_input.hcp.chain_state.best_block_hash[12..32]
                .try_into()
                .map_err(|_| BridgeCircuitHostParamsError::InvalidKickoffTx)?;

        let payout_tx_block_hash: PayoutTxBlockhash = bridge_circuit_input
            .payout_spv
            .block_header
            .compute_block_hash()[12..32]
            .try_into()
            .map_err(|_| BridgeCircuitHostParamsError::InvalidKickoffTx)?;

        let deposit_constant = host_deposit_constant(&bridge_circuit_input)?;
        let watchtower_challenge_set = verify_watchtower_challenges(&bridge_circuit_input);

        Ok(Self {
            bridge_circuit_input,
            challenge_sending_watchtowers: ChallengeSendingWatchtowers(
                watchtower_challenge_set.challenge_senders,
            ),
            deposit_constant,
            payout_tx_block_hash,
            latest_block_hash,
        })
    }

    /// Calculates the host journal hash for the bridge circuit.
    ///
    /// # Returns
    ///
    /// Returns a `blake3::Hash` representing the journal hash.
    pub fn host_journal_hash(&self) -> blake3::Hash {
        journal_hash(
            self.payout_tx_block_hash,
            self.latest_block_hash,
            self.challenge_sending_watchtowers,
            self.deposit_constant,
        )
    }
}

/// Calculates the deposit constant from bridge circuit input.
///
/// # Arguments
///
/// * `input` - The bridge circuit input containing deposit information
///
/// # Returns
///
/// Returns a `Result` containing the `DepositConstant` or an error.
///
/// # Errors
///
/// This function will return an error if:
/// - Transaction output is missing
/// - Storage proof deserialization fails
/// - Operator public key parsing fails
/// - Round transaction ID validation fails
fn host_deposit_constant(
    input: &BridgeCircuitInput,
) -> Result<DepositConstant, BridgeCircuitHostParamsError> {
    let last_output = input
        .payout_spv
        .transaction
        .output
        .last()
        .ok_or(BridgeCircuitHostParamsError::MissingKickoffOutputs)?;

    let deposit_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&input.sp.storage_proof_deposit_txid).map_err(|e| {
            BridgeCircuitHostParamsError::StorageProofDeserializationError(e.to_string())
        })?;

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
        return Err(BridgeCircuitHostParamsError::RoundTxidMismatch);
    }

    let kickff_round_vout = input.kickoff_tx.input[0].previous_output.vout;

    let operator_xonlypk: [u8; 32] = parse_op_return_data(&last_output.script_pubkey)
        .ok_or(BridgeCircuitHostParamsError::InvalidOperatorPubkey)?
        .try_into()
        .map_err(|_| BridgeCircuitHostParamsError::InvalidOperatorPubkey)?;

    let deposit_value_bytes: [u8; 32] = deposit_storage_proof.value.to_be_bytes::<32>();

    Ok(deposit_constant(
        operator_xonlypk,
        input.watchtower_challenge_connector_start_idx,
        &input.all_tweaked_watchtower_pubkeys,
        deposit_value_bytes,
        round_txid,
        kickff_round_vout,
        input.hcp.genesis_state_hash,
    ))
}

/// Inputs required for BitVM2 bridge circuit verification.
///
/// This struct contains all the inputs needed to verify a bridge circuit proof
/// in the BitVM2 system, including block hashes, watchtower data, and method IDs.
#[derive(Debug, Clone, Copy)]
pub struct BridgeCircuitBitvmInputs {
    pub payout_tx_block_hash: [u8; 20],
    pub latest_block_hash: [u8; 20],
    pub challenge_sending_watchtowers: [u8; 20],
    pub deposit_constant: [u8; 32],
    pub combined_method_id: [u8; 32],
}

impl BridgeCircuitBitvmInputs {
    /// Creates a new instance of BridgeCircuitBitvmInputs.
    ///
    /// # Arguments
    ///
    /// * `payout_tx_block_hash` - Hash of the block containing the payout transaction
    /// * `latest_block_hash` - Hash of the latest block in the chain
    /// * `challenge_sending_watchtowers` - Hash representing watchtowers that sent challenges
    /// * `deposit_constant` - Constant value representing the deposit
    /// * `combined_method_id` - Combined method ID for the circuit
    ///
    /// # Returns
    ///
    /// Returns a new instance of `BridgeCircuitBitvmInputs`.
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

    /// Calculates the Groth16 public input for the bridge circuit.
    ///
    /// This method computes the public input hash used in Groth16 proof verification
    /// by combining all the input data in a specific order.
    ///
    /// # Returns
    ///
    /// Returns a `blake3::Hash` representing the public input.
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

    /// Verifies a bridge circuit Groth16 proof.
    ///
    /// This method verifies that a given Groth16 proof is valid for this bridge circuit
    /// by computing the expected public input and verifying the proof against it.
    ///
    /// # Arguments
    ///
    /// * `proof` - The Groth16 proof to verify
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing `true` if the proof is valid, or an error if verification fails.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - Proof verification fails
    /// - Public input calculation fails
    /// - Verifying key retrieval fails
    pub fn verify_bridge_circuit(
        &self,
        proof: ark_groth16::Proof<Bn254>,
    ) -> Result<bool, BridgeCircuitHostParamsError> {
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
        .map_err(|_| BridgeCircuitHostParamsError::ProofVerificationFailed)
    }
}
