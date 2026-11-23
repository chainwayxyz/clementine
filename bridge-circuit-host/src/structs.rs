use alloy_rpc_types::EIP1186StorageProof;
use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    sighash::Annex,
    taproot::TAPROOT_ANNEX_PREFIX,
    Network, OutPoint, Transaction, TxOut, Txid, Witness, XOnlyPublicKey,
};
use borsh::{BorshDeserialize, BorshSerialize};
use circuits_lib::common::sp1::Receipt;
use circuits_lib::{
    bridge_circuit::{
        bridge_public_values, deposit_constant, get_first_op_return_output, parse_op_return_data,
        spv::SPV,
        structs::{
            BridgeCircuitInput, ChallengeSendingWatchtowers, DepositConstant, LatestBlockhash,
            LightClientProof, PayoutTxBlockhash, StorageProof, WatchtowerInput,
        },
        transaction::CircuitTransaction,
        verify_watchtower_challenges,
    },
    header_chain::BlockHeaderCircuitOutput,
};
use eyre::Result;
use std::ops::{Deref, DerefMut};

use thiserror::Error;

const OP_RETURN_OUTPUT: usize = 1;
const ANCHOR_OUTPUT: usize = 1;

/// Parameters required for bridge circuit proof generation.
///
/// This struct contains all the necessary inputs and proofs required to generate
/// a bridge circuit proof, including transactions, receipts, and cryptographic proofs.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BridgeCircuitHostParams {
    pub kickoff_tx: CircuitTransaction,
    pub spv: SPV,
    pub headerchain_receipt: Receipt,
    pub lcp_receipt: Receipt,
    pub storage_proof: StorageProof,
    pub network: CircuitNetwork,
    pub watchtower_inputs: Vec<WatchtowerInput>,
    pub all_tweaked_watchtower_pubkeys: Vec<[u8; 32]>,
    pub watchtower_challenge_connector_start_idx: u32,
    pub payout_input_index: u32,
}

/// Errors that can occur when constructing or validating bridge circuit host parameters.
#[derive(Debug, Clone, Error)]
pub enum BridgeCircuitHostParamsError {
    #[error("Invalid kickoff transaction")]
    InvalidKickoffTx,
    #[error("Invalid headerchain receipt")]
    InvalidHeaderchainReceipt,
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
    #[error("Failed to verify bridge circuit proof")]
    ProofVerificationFailed,
}

impl BridgeCircuitHostParams {
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
    /// - Public key extraction from kickoff transaction fails
    /// - Storage proof deserialization fails
    /// - Payout input index calculation fails
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_wt_tx(
        kickoff_tx: Transaction,
        spv: SPV,
        headerchain_receipt: Receipt,
        lcp_receipt: Receipt,
        storage_proof: StorageProof,
        network: Network,
        watchtower_contexts: &[WatchtowerContext],
        watchtower_challenge_connector_start_idx: u32,
    ) -> Result<Self, BridgeCircuitHostParamsError> {
        let watchtower_inputs = get_wt_inputs(
            kickoff_tx.compute_txid(),
            watchtower_contexts,
            watchtower_challenge_connector_start_idx,
        )?;

        let all_tweaked_watchtower_pubkeys =
            get_all_pubkeys(&kickoff_tx, watchtower_challenge_connector_start_idx)?
                .iter()
                .map(XOnlyPublicKey::serialize)
                .collect();

        let storage_proof_utxo: EIP1186StorageProof =
            serde_json::from_str(&storage_proof.storage_proof_utxo).map_err(|e| {
                BridgeCircuitHostParamsError::StorageProofDeserializationError(e.to_string())
            })?;

        let wd_txid_bytes: [u8; 32] = storage_proof_utxo.value.to_be_bytes();

        let wd_txid: Txid = bitcoin::consensus::deserialize(&wd_txid_bytes)
            .map_err(|_| BridgeCircuitHostParamsError::InvalidStorageProof)?;

        let storage_proof_vout: EIP1186StorageProof =
            serde_json::from_str(&storage_proof.storage_proof_vout).map_err(|e| {
                BridgeCircuitHostParamsError::StorageProofDeserializationError(e.to_string())
            })?;

        // Same decoding as the bridge circuit's storage proof verification
        let wd_vout_bytes: [u8; 32] = storage_proof_vout.value.to_be_bytes();
        let wd_vout = u32::from_le_bytes(
            wd_vout_bytes[28..32]
                .try_into()
                .map_err(|_| BridgeCircuitHostParamsError::InvalidStorageProof)?,
        );

        let payout_input_index = get_payout_input_index(
            OutPoint {
                txid: wd_txid,
                vout: wd_vout,
            },
            &spv.transaction.0,
        )?;

        Ok(BridgeCircuitHostParams {
            kickoff_tx: CircuitTransaction(kickoff_tx),
            spv,
            headerchain_receipt,
            lcp_receipt,
            storage_proof,
            network: CircuitNetwork(network),
            watchtower_inputs,
            all_tweaked_watchtower_pubkeys,
            watchtower_challenge_connector_start_idx,
            payout_input_index,
        })
    }

    /// Builds the bridge guest input. The header chain output and the light client input come
    /// from their receipts.
    pub fn bridge_circuit_input(&self) -> Result<BridgeCircuitInput, BridgeCircuitHostParamsError> {
        let header_chain_output: BlockHeaderCircuitOutput =
            borsh::from_slice(&self.headerchain_receipt.journal.bytes)
                .map_err(|_| BridgeCircuitHostParamsError::InvalidHeaderchainReceipt)?;
        Ok(BridgeCircuitInput::new(
            self.kickoff_tx.clone().into(),
            self.watchtower_inputs.clone(),
            self.all_tweaked_watchtower_pubkeys.clone(),
            header_chain_output,
            self.spv.clone(),
            self.payout_input_index,
            LightClientProof::from_receipt(&self.lcp_receipt),
            self.storage_proof.clone(),
            self.watchtower_challenge_connector_start_idx,
        ))
    }
}

/// Finds the index of the payout input in the payout transaction based on the withdrawal outpoint.
///
/// # Arguments
///
/// * `wd_outpoint` - The withdrawal outpoint to search for
/// * `payout_tx` - The payout transaction to search within
///
/// # Returns
///
/// Returns a `Result` containing the input index as `u32` or an error.
///
/// # Errors
///
/// This function will return an error if:
/// - The withdrawal outpoint is not spent by any input
/// - The input index is too large to fit in a `u32`
fn get_payout_input_index(
    wd_outpoint: OutPoint,
    payout_tx: &Transaction,
) -> Result<u32, BridgeCircuitHostParamsError> {
    for (index, input) in payout_tx.input.iter().enumerate() {
        if input.previous_output == wd_outpoint {
            return u32::try_from(index).map_err(|_| {
                // This should never happen
                BridgeCircuitHostParamsError::PayoutInputIndexTooLarge(index)
            });
        }
    }
    Err(BridgeCircuitHostParamsError::PayoutInputIndexNotFound)
}

/// Generates watchtower inputs from watchtower contexts.
///
/// Each context carries the watchtower index matched by the state machine, so reconstruction
/// uses the exact kickoff connector for that watchtower.
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
    watchtower_challenge_connector_start_idx: u32,
) -> Result<Vec<WatchtowerInput>, BridgeCircuitHostParamsError> {
    watchtower_contexts
        .iter()
        .map(|context| {
            get_wt_input(
                kickoff_tx_id,
                context,
                watchtower_challenge_connector_start_idx,
            )
        })
        .collect()
}

fn get_wt_input(
    kickoff_tx_id: Txid,
    context: &WatchtowerContext,
    watchtower_challenge_connector_start_idx: u32,
) -> Result<WatchtowerInput, BridgeCircuitHostParamsError> {
    let expected_vout = watchtower_challenge_connector_start_idx
        .checked_add(
            context
                .watchtower_idx
                .checked_mul(2)
                .ok_or(BridgeCircuitHostParamsError::InvalidWatchtowerInputs)?,
        )
        .ok_or(BridgeCircuitHostParamsError::InvalidWatchtowerInputs)?;

    let input_idx = context
        .watchtower_tx
        .input
        .iter()
        .position(|input| {
            input.previous_output.txid == kickoff_tx_id
                && input.previous_output.vout == expected_vout
        })
        .ok_or(BridgeCircuitHostParamsError::InvalidWatchtowerInputs)?;

    let prevouts = context
        .watchtower_tx
        .input
        .iter()
        .map(|input| {
            let tx = context
                .prevout_txs
                .iter()
                .find(|tx| tx.compute_txid() == input.previous_output.txid)
                .ok_or(BridgeCircuitHostParamsError::InvalidWatchtowerInputs)?;
            tx.output
                .get(input.previous_output.vout as usize)
                .cloned()
                .ok_or(BridgeCircuitHostParamsError::InvalidWatchtowerInputs)
        })
        .collect::<Result<Vec<TxOut>, _>>()?;

    let input = &context.watchtower_tx.input[input_idx];
    let signature = input
        .witness
        .nth(0)
        .ok_or(BridgeCircuitHostParamsError::InvalidWatchtowerInputs)?;

    let mut witness = Witness::new();
    witness.push(signature);

    let annex_digest = if input.witness.len() <= 1 {
        None
    } else {
        input.witness.last().and_then(|last_witness_element| {
            if last_witness_element.first() != Some(&TAPROOT_ANNEX_PREFIX) {
                return None;
            }

            let annex = Annex::new(last_witness_element).ok()?;
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc).ok()?;
            Some(sha256::Hash::from_engine(enc).to_byte_array())
        })
    };

    let mut watchtower_tx = context.watchtower_tx.clone();
    for input in &mut watchtower_tx.input {
        input.witness.clear();
    }

    WatchtowerInput::new(
        context.watchtower_idx,
        u32::try_from(input_idx)
            .map_err(|_| BridgeCircuitHostParamsError::InvalidWatchtowerInputs)?,
        prevouts,
        watchtower_tx,
        witness,
        annex_digest,
    )
    .map_err(|_| BridgeCircuitHostParamsError::InvalidWatchtowerInputs)
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
    watchtower_challenge_connector_start_idx: u32,
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

/// Context containing the matched watchtower index, watchtower transaction, and transactions that
/// include prevouts.
pub struct WatchtowerContext {
    pub watchtower_idx: u32,
    pub watchtower_tx: Transaction,
    pub prevout_txs: Vec<Transaction>,
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
    let first_op_return_output = get_first_op_return_output(&input.payout_spv.transaction)
        .ok_or(BridgeCircuitHostParamsError::InvalidOperatorPubkey)?;

    let deposit_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&input.sp.storage_proof_deposit_txid).map_err(|e| {
            BridgeCircuitHostParamsError::StorageProofDeserializationError(e.to_string())
        })?;

    let round_txid = input.kickoff_tx.input[0]
        .previous_output
        .txid
        .to_byte_array();

    let kickoff_round_vout = input.kickoff_tx.input[0].previous_output.vout;

    let operator_xonlypk: [u8; 32] = parse_op_return_data(&first_op_return_output.script_pubkey)
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
        kickoff_round_vout,
        input.hcp.genesis_state_hash,
    ))
}

/// Values the bridge guest commits and the operator commits for BitVM.
#[derive(Debug, Clone, Copy)]
pub struct BridgeCircuitBitvmInputs {
    pub payout_tx_block_hash: [u8; 20],
    pub latest_block_hash: [u8; 20],
    pub challenge_sending_watchtowers: [u8; 20],
    pub deposit_constant: [u8; 32],
}

impl BridgeCircuitBitvmInputs {
    /// Computes on the host the values that the bridge guest commits for `input`.
    pub fn from_input(input: &BridgeCircuitInput) -> Result<Self, BridgeCircuitHostParamsError> {
        let latest_block_hash = input.hcp.chain_state.best_block_hash[12..32]
            .try_into()
            .map_err(|_| BridgeCircuitHostParamsError::InvalidKickoffTx)?;
        let payout_tx_block_hash = input.payout_spv.block_header.compute_block_hash()[12..32]
            .try_into()
            .map_err(|_| BridgeCircuitHostParamsError::InvalidKickoffTx)?;
        Ok(Self {
            payout_tx_block_hash,
            latest_block_hash,
            challenge_sending_watchtowers: verify_watchtower_challenges(input).challenge_senders,
            deposit_constant: host_deposit_constant(input)?.0,
        })
    }

    /// The 64-byte `deposit_constant || X` output committed by the bridge guest.
    pub fn public_values(&self) -> [u8; 64] {
        bridge_public_values(
            PayoutTxBlockhash(self.payout_tx_block_hash),
            LatestBlockhash(self.latest_block_hash),
            ChallengeSendingWatchtowers(self.challenge_sending_watchtowers),
            DepositConstant(self.deposit_constant),
        )
    }

    /// The single Groth16 public input of the bridge proof: SP1's BLAKE3 digest of the
    /// committed 64-byte output.
    pub fn groth16_public_input(&self) -> ark_bn254::Fr {
        circuits_lib::common::sp1::groth16::public_input_blake3(&self.public_values())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct CircuitNetwork(pub Network);

impl CircuitNetwork {
    pub fn from(network: Network) -> Self {
        Self(network)
    }

    pub fn inner(&self) -> &Network {
        &self.0
    }
}

impl BorshSerialize for CircuitNetwork {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&(self.0 as u8), writer)
    }
}

impl BorshDeserialize for CircuitNetwork {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let value = u8::deserialize_reader(reader)?;
        let network = match value {
            0 => Network::Bitcoin,
            1 => Network::Testnet,
            2 => Network::Testnet4,
            3 => Network::Signet,
            4 => Network::Regtest,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid Network",
                ))
            }
        };
        Ok(Self(network))
    }
}

impl Deref for CircuitNetwork {
    type Target = Network;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CircuitNetwork {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Network> for CircuitNetwork {
    fn from(network: Network) -> Self {
        Self(network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, TxIn};

    #[test]
    fn payout_input_index_matches_txid_and_vout() {
        let wd_txid = Txid::from_byte_array([1; 32]);
        let input = |vout| TxIn {
            previous_output: OutPoint {
                txid: wd_txid,
                vout,
            },
            ..Default::default()
        };
        let payout_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input(0), input(3)],
            output: vec![],
        };

        let wd_outpoint = OutPoint {
            txid: wd_txid,
            vout: 3,
        };
        assert_eq!(get_payout_input_index(wd_outpoint, &payout_tx).unwrap(), 1);

        let missing_outpoint = OutPoint {
            txid: wd_txid,
            vout: 1,
        };
        assert!(matches!(
            get_payout_input_index(missing_outpoint, &payout_tx),
            Err(BridgeCircuitHostParamsError::PayoutInputIndexNotFound)
        ));
    }
}
