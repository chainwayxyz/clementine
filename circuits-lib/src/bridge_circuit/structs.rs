//! # Bridge Circuit Structs
//! This module defines the data structures used in the Bridge Circuit.
//! It includes structures for light client proofs, work-only circuit outputs, and various constants used in the circuit.
//! ## Key Structures
//! - **LightClientProof:** Represents a light client proof with a journal and L2 height.
//! - **WorkOnlyCircuitOutput:** Represents the output of a work-only circuit, including work done and genesis state hash.
//! - **WatchTowerChallengeTxCommitment:** Represents a commitment to a watchtower challenge transaction, including the Groth16 proof and total work.
//! - **WithdrawalOutpointTxid:** Represents the transaction ID (txid) of a withdrawal outpoint.
//! - **MoveTxid:** Represents the transaction ID (txid) of a move-to-vault transaction.
//! - **StorageProof:** Represents the storage proof for Ethereum, including UTXO, vout, and deposit proofs.
//! - **WatchtowerInput:** Represents the input for a watchtower, including the watchtower index, challenge inputs, and transaction details.

use std::ops::{Deref, DerefMut};

use crate::common::constants::MAX_NUMBER_OF_WATCHTOWERS;
use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    sighash::Annex,
    taproot::TAPROOT_ANNEX_PREFIX,
    Amount, ScriptBuf, Transaction, TxOut, Txid, Witness,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::header_chain::BlockHeaderCircuitOutput;

use super::{spv::SPV, transaction::CircuitTransaction};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct WithdrawalOutpointTxid(pub [u8; 32]);

impl Deref for WithdrawalOutpointTxid {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct MoveTxid(pub [u8; 32]);

impl Deref for MoveTxid {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represents a constant value used for each deposit in the bridge circuit.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct DepositConstant(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct ChallengeSendingWatchtowers(pub [u8; 20]);

impl Deref for ChallengeSendingWatchtowers {
    type Target = [u8; 20];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct PayoutTxBlockhash(pub [u8; 20]);

impl TryFrom<&[u8]> for PayoutTxBlockhash {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 20] = value
            .try_into()
            .map_err(|_| "Expected 20 bytes for PayoutTxBlockhash")?;
        Ok(PayoutTxBlockhash(arr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct LatestBlockhash(pub [u8; 20]);

impl TryFrom<&[u8]> for LatestBlockhash {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 20] = value
            .try_into()
            .map_err(|_| "Expected 20 bytes for LatestBlockhash")?;
        Ok(LatestBlockhash(arr))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, BorshDeserialize, BorshSerialize)]
pub struct TotalWork(pub [u8; 16]);

impl Deref for TotalWork {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for TotalWork {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 16] = value
            .try_into()
            .map_err(|_| "Expected 16 bytes for TotalWork")?;
        Ok(TotalWork(arr))
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WorkOnlyCircuitInput {
    pub header_chain_circuit_output: BlockHeaderCircuitOutput,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WorkOnlyCircuitOutput {
    pub work_u128: [u8; 16],
    pub genesis_state_hash: [u8; 32],
}

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WatchTowerChallengeTxCommitment {
    pub compressed_g16_proof: [u8; 128],
    pub total_work: [u8; 16],
}

#[derive(Debug, Clone, Eq, PartialEq, BorshDeserialize, BorshSerialize, Default)]
pub struct LightClientProof {
    pub lc_journal: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, BorshDeserialize, BorshSerialize, Default)]
pub struct StorageProof {
    pub storage_proof_utxo: String,         // This will be an Outpoint
    pub storage_proof_vout: String,         // This is the vout of the txid
    pub storage_proof_deposit_txid: String, // This is the txid of the deposit tx
    pub index: u32, // This is the index of the storage proof in the contract
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WatchtowerInput {
    pub watchtower_idx: u16,                           // Which watchtower this is
    pub watchtower_challenge_input_idx: u16, // Which input index this challenge connector txout goes to
    pub watchtower_challenge_utxos: Vec<CircuitTxOut>, // BridgeCircuitUTXO TxOut serialized and all the prevouts for watchtower challenge tx, Vec<TxOut>
    pub watchtower_challenge_tx: CircuitTransaction, // BridgeCircuitTransaction challenge tx itself for each watchtower
    pub watchtower_challenge_witness: CircuitWitness, // Witness
    pub annex_digest: Option<[u8; 32]>, // Optional annex digest for the watchtower challenge tx
}

impl WatchtowerInput {
    pub fn new(
        watchtower_idx: u16,
        watchtower_challenge_input_idx: u16,
        watchtower_challenge_utxos: Vec<TxOut>,
        watchtower_challenge_tx: Transaction,
        watchtower_challenge_witness: Witness,
        annex_digest: Option<[u8; 32]>,
    ) -> Result<Self, &'static str> {
        if watchtower_idx as usize >= MAX_NUMBER_OF_WATCHTOWERS {
            return Err("Watchtower index out of bounds");
        }

        let watchtower_challenge_tx = CircuitTransaction::from(watchtower_challenge_tx);

        let watchtower_challenge_witness: CircuitWitness =
            CircuitWitness::from(watchtower_challenge_witness);

        let watchtower_challenge_utxos: Vec<CircuitTxOut> = watchtower_challenge_utxos
            .into_iter()
            .map(CircuitTxOut::from)
            .collect::<Vec<CircuitTxOut>>();

        Ok(Self {
            watchtower_idx,
            watchtower_challenge_input_idx,
            watchtower_challenge_utxos,
            watchtower_challenge_tx,
            watchtower_challenge_witness,
            annex_digest,
        })
    }

    /// Constructs a `WatchtowerInput` instance from the kickoff transaction, the watchtower transaction and
    /// an optional slice of previous transactions.
    ///
    /// # Parameters
    /// - `kickoff_tx_id`: The kickoff transaction id whose output is consumed by an input of the watchtower transaction
    /// - `watchtower_tx`: The watchtower challenge transaction that includes an input referencing the `kickoff_tx`
    /// - `prevout_txs`: A slice of transactions, each including at least one output spent as input in `watchtower_tx`
    /// - `watchtower_challenge_connector_start_idx`: Starting index for watchtower challenge connectors
    ///
    /// # Returns
    /// Result containing the WatchtowerInput or an error message
    ///
    /// # Note
    ///
    /// All previous transactions other than kickoff tx whose outputs are spent by the `watchtower_tx`
    /// should be supplied in `prevout_txs` if they exist.
    ///
    /// # Errors
    ///
    /// This function will return errors if:
    /// - The kickoff transaction is not referenced by any input in the watchtower transaction.
    /// - The output index underflows when computing the watchtower index.
    /// - The watchtower index exceeds `MAX_NUMBER_OF_WATCHTOWERS`.
    /// - A previous transaction required to resolve an input is not provided.
    /// - An output referenced by an input is missing or out of bounds.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The watchtower index cannot be converted to `u8` (should be unreachable due to earlier bounds check).
    ///
    pub fn from_txs(
        kickoff_tx_id: Txid,
        watchtower_tx: Transaction,
        prevout_txs: &[Transaction],
        watchtower_challenge_connector_start_idx: u16,
    ) -> Result<Self, &'static str> {
        let watchtower_challenge_input_idx = watchtower_tx
            .input
            .iter()
            .position(|input| input.previous_output.txid == kickoff_tx_id)
            .map(|ind| ind as u16)
            .ok_or("Kickoff txid not found in watchtower inputs")?;

        let output_index = watchtower_tx.input[watchtower_challenge_input_idx as usize]
            .previous_output
            .vout as usize;

        let watchtower_index = output_index
            .checked_sub(watchtower_challenge_connector_start_idx as usize)
            .ok_or("Output index underflow")?
            / 2;

        if watchtower_index >= MAX_NUMBER_OF_WATCHTOWERS {
            return Err("Watchtower index out of bounds");
        }

        let watchtower_idx =
            u16::try_from(watchtower_index).expect("Cannot fail, already checked bounds");

        let watchtower_challenge_utxos: Vec<CircuitTxOut> = watchtower_tx
            .input
            .iter()
            .map(|input| {
                let txid = input.previous_output.txid;
                let vout = input.previous_output.vout as usize;

                let tx = prevout_txs
                    .iter()
                    .find(|tx| tx.compute_txid() == txid)
                    .ok_or("Previous transaction not found")?;

                let tx_out = tx
                    .output
                    .get(vout)
                    .cloned()
                    .ok_or("Output index out of bounds")?;

                Ok::<CircuitTxOut, &'static str>(CircuitTxOut::from(tx_out))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut watchtower_challenge_tx = CircuitTransaction::from(watchtower_tx);

        let watchtower_challenge_annex: Option<Annex> = {
            // If there are at most one element in the witness, then there are no annexes
            if watchtower_challenge_tx.input[watchtower_challenge_input_idx as usize]
                .witness
                .len()
                <= 1
            {
                None
            }
            // Otherwise, if the last element starts with 0x50, then it is an Annex
            else if let Some(last_witness_element) = watchtower_challenge_tx.input
                [watchtower_challenge_input_idx as usize]
                .witness
                .last()
            {
                // Check if the first byte is 0x50 before attempting to create an Annex
                // This avoids creating a Result that we immediately unwrap or map to None
                if last_witness_element.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    Annex::new(last_witness_element).ok() // Convert Result<Annex, AnnexError> to Option<Annex>
                } else {
                    None
                }
            } else {
                None
            }
        };

        let annex_digest: Option<[u8; 32]> = watchtower_challenge_annex.and_then(|annex| {
            // Use and_then to flatten the Option<Option<T>> to Option<T>
            let mut enc = sha256::Hash::engine();
            match annex.consensus_encode(&mut enc) {
                Ok(_) => {
                    // Discard the usize, we only care if it succeeded
                    let hash = sha256::Hash::from_engine(enc);
                    Some(hash.to_byte_array()) // Use to_byte_array() for owned array
                }
                Err(_) => {
                    // Handle the error during encoding, e.g., log it or return None
                    // For now, returning None if encoding fails
                    None
                }
            }
        });

        // Get the first witness item, returning an error if it doesn't exist.
        let Some(signature) = watchtower_challenge_tx.input
            [watchtower_challenge_input_idx as usize]
            .witness
            .nth(0)
        else {
            return Err("Watchtower challenge input witness is empty");
        };

        // The rest of the logic proceeds with the guaranteed `signature`.
        let mut witness = Witness::new();
        witness.push(signature);

        let watchtower_challenge_witness = CircuitWitness::from(witness);

        for input in &mut watchtower_challenge_tx.input {
            input.witness.clear();
        }

        Ok(Self {
            watchtower_idx,
            watchtower_challenge_input_idx,
            watchtower_challenge_utxos,
            watchtower_challenge_tx,
            watchtower_challenge_witness,
            annex_digest,
        })
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BridgeCircuitInput {
    pub kickoff_tx: CircuitTransaction,
    // Add all watchtower pubkeys as global input as Vec<[u8; 32]> Which should be shorter than or equal to 160 elements
    pub all_tweaked_watchtower_pubkeys: Vec<[u8; 32]>, // Per watchtower [u8; 34] or OP_PUSHNUM_1 OP_PUSHBYTES_32 <TweakedXOnlyPublicKey> which is [u8; 32]
    pub watchtower_inputs: Vec<WatchtowerInput>,
    pub hcp: BlockHeaderCircuitOutput,
    pub payout_spv: SPV,
    pub payout_input_index: u16,
    pub lcp: LightClientProof,
    pub sp: StorageProof,
    pub watchtower_challenge_connector_start_idx: u16,
}

#[allow(clippy::too_many_arguments)]
impl BridgeCircuitInput {
    pub fn new(
        kickoff_tx: Transaction,
        watchtower_inputs: Vec<WatchtowerInput>,
        all_tweaked_watchtower_pubkeys: Vec<[u8; 32]>,
        hcp: BlockHeaderCircuitOutput,
        payout_spv: SPV,
        payout_input_index: u16,
        lcp: LightClientProof,
        sp: StorageProof,
        watchtower_challenge_connector_start_idx: u16,
    ) -> Self {
        Self {
            kickoff_tx: CircuitTransaction::from(kickoff_tx),
            watchtower_inputs,
            hcp,
            payout_spv,
            payout_input_index,
            lcp,
            sp,
            all_tweaked_watchtower_pubkeys,
            watchtower_challenge_connector_start_idx,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct WatchtowerChallengeSet {
    pub challenge_senders: [u8; 20],
    pub challenge_outputs: Vec<Vec<TxOut>>,
}

fn serialize_txout<W: borsh::io::Write>(txout: &TxOut, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txout.value.to_sat(), writer)?;
    BorshSerialize::serialize(&txout.script_pubkey.as_bytes(), writer)
}

fn deserialize_txout<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxOut> {
    let value = Amount::from_sat(u64::deserialize_reader(reader)?);
    let script_pubkey = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);

    Ok(TxOut {
        value,
        script_pubkey,
    })
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct CircuitTxOut(pub TxOut);

impl CircuitTxOut {
    pub fn from(tx_out: TxOut) -> Self {
        Self(tx_out)
    }

    pub fn inner(&self) -> &TxOut {
        &self.0
    }
}

impl BorshSerialize for CircuitTxOut {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        serialize_txout(&self.0, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for CircuitTxOut {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let tx_out = deserialize_txout(reader)?;
        Ok(Self(tx_out))
    }
}

impl Deref for CircuitTxOut {
    type Target = TxOut;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CircuitTxOut {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<TxOut> for CircuitTxOut {
    fn from(tx_out: TxOut) -> Self {
        Self(tx_out)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct CircuitWitness(pub Witness);

impl CircuitWitness {
    pub fn from(witness: Witness) -> Self {
        Self(witness)
    }

    pub fn inner(&self) -> &Witness {
        &self.0
    }
}

impl BorshSerialize for CircuitWitness {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_vec(), writer)?;
        Ok(())
    }
}

impl BorshDeserialize for CircuitWitness {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let witness_data = Vec::<Vec<u8>>::deserialize_reader(reader)?;
        let witness = Witness::from(witness_data);
        Ok(Self(witness))
    }
}

impl Deref for CircuitWitness {
    type Target = Witness;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CircuitWitness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Witness> for CircuitWitness {
    fn from(witness: Witness) -> Self {
        Self(witness)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash, Copy)]
pub struct CircuitTxid(pub Txid);

impl CircuitTxid {
    pub fn from(tx_id: Txid) -> Self {
        Self(tx_id)
    }

    pub fn inner(&self) -> &Txid {
        &self.0
    }
}

impl BorshSerialize for CircuitTxid {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0.as_byte_array(), writer)?;
        Ok(())
    }
}

impl BorshDeserialize for CircuitTxid {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let tx_data: [u8; 32] =
            Vec::<u8>::deserialize_reader(reader)?
                .try_into()
                .map_err(|_| {
                    borsh::io::Error::new(
                        borsh::io::ErrorKind::InvalidData,
                        "Failed to convert Vec<u8> to [u8; 32]",
                    )
                })?;

        let tx_id = Txid::from_byte_array(tx_data);

        Ok(Self(tx_id))
    }
}

impl Deref for CircuitTxid {
    type Target = Txid;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CircuitTxid {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Txid> for CircuitTxid {
    fn from(tx_id: Txid) -> Self {
        Self(tx_id)
    }
}
