use std::ops::{Deref, DerefMut};

use crate::common::constants::{
    FIRST_FIVE_OUTPUTS, MAX_NUMBER_OF_WATCHTOWERS, NUMBER_OF_ASSERT_TXS,
};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use final_spv::{spv::SPV, transaction::CircuitTransaction};
use header_chain::header_chain::BlockHeaderCircuitOutput;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WorkOnlyCircuitInput {
    pub header_chain_circuit_output: BlockHeaderCircuitOutput,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WorkOnlyCircuitOutput {
    pub work_u128: [u32; 4],
}

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WatchTowerChallengeTxCommitment {
    pub compressed_g16_proof: [u8; 128],
    pub total_work: [u8; 16],
}

#[derive(Debug, Clone, Eq, PartialEq, BorshDeserialize, BorshSerialize, Default)]
pub struct LightClientProof {
    pub lc_journal: Vec<u8>,
    pub l2_height: String,
}

#[derive(Debug, Clone, Eq, PartialEq, BorshDeserialize, BorshSerialize, Default)]
pub struct StorageProof {
    pub storage_proof_utxo: String, // This will be an Outpoint but only a txid is given
    pub storage_proof_deposit_idx: String, // This is the index of the withdrawal
    pub index: u32,                 // For now this is 18, for a specifix withdrawal
}

// #[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
// pub struct WatchtowerInputs {
//     pub watchtower_idxs: Vec<u8>, // Which watchtower this is
//     pub watchtower_pubkeys: Vec<Vec<u8>>, // We do not know what these will be for sure right now
//     pub watchtower_challenge_input_idxs: Vec<u8>,
//     pub watchtower_challenge_utxos: Vec<Vec<Vec<u8>>>, // BridgeCircuitUTXO
//     pub watchtower_challenge_txs: Vec<Vec<u8>>, // BridgeCircuitTransaction
//     pub watchtower_challenge_witnesses: Vec<Vec<u8>>, // BridgeCircuitTransactionWitness Vec<Some(Witness)>
// }

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WatchtowerInput {
    pub watchtower_idx: u8,                            // Which watchtower this is
    pub watchtower_challenge_input_idx: u8, // Which input index this challenge connector txout goes to
    pub watchtower_challenge_utxos: Vec<CircuitTxOut>, // BridgeCircuitUTXO TxOut serialized and all the prevouts for watchtower challenge tx, Vec<TxOut>
    pub watchtower_challenge_tx: CircuitTransaction, // BridgeCircuitTransaction challenge tx itself for each watchtower
    pub watchtower_challenge_witness: CircuitWitness, // Witness
}

impl WatchtowerInput {
    pub fn new(
        watchtower_idx: u8,
        watchtower_challenge_input_idx: u8,
        watchtower_challenge_utxos: Vec<TxOut>,
        watchtower_challenge_tx: Transaction,
        watchtower_challenge_witness: Witness,
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
        })
    }

    /// Constructs a `WatchtowerInput` instance from the kickoff transaction, the watchtower transaction and
    /// an optional slice of previous transactions.
    ///
    /// # Arguments
    ///
    /// - `kickoff_tx`: The kickoff transaction whose output is consumed by an input of the watchtower transaction.
    /// * `watchtower_tx` - The watchtower challenge transaction that includes an input
    ///   referencing the `kickoff_tx`.
    /// * `previous_txs` - An optional slice of transactions, each of which should include
    ///   at least one output that is later spent as an input in `watchtower_tx`.
    ///
    /// # Note
    ///
    /// All previous transactions whose outputs are spent by the `watchtower_tx`
    /// should be supplied in `previous_txs` if they exist.
    ///
    /// # Returns
    ///
    /// Returns `Ok(WatchtowerInput)` if all required data is successfully extracted and validated.
    /// Returns `Err(&'static str)` if any error occurs during the process.
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
        kickoff_tx: &Transaction,
        watchtower_tx: Transaction,
        previous_txs: Option<&[Transaction]>,
    ) -> Result<Self, &'static str> {
        let kickoff_txid = kickoff_tx.compute_txid();

        let watchtower_challenge_input_idx = watchtower_tx
            .input
            .iter()
            .position(|input| input.previous_output.txid == kickoff_txid)
            .map(|ind| ind as u8)
            .ok_or("Kickoff txid not found in watchtower inputs")?;

        let output_index = watchtower_tx.input[watchtower_challenge_input_idx as usize]
            .previous_output
            .vout as usize;

        let watchtower_index = output_index
            .checked_sub(FIRST_FIVE_OUTPUTS + NUMBER_OF_ASSERT_TXS)
            .ok_or("Output index underflow")?
            / 2;

        if watchtower_index >= MAX_NUMBER_OF_WATCHTOWERS {
            return Err("Watchtower index out of bounds");
        }

        let watchtower_idx =
            u8::try_from(watchtower_index).expect("Cannot fail, already checked bounds");

        let previous_txs = previous_txs.unwrap_or(&[]);

        let mut all_previous_txs: Vec<Transaction> = Vec::with_capacity(previous_txs.len() + 1);
        all_previous_txs.push(kickoff_tx.clone());
        all_previous_txs.extend_from_slice(previous_txs);

        let watchtower_challenge_utxos: Vec<CircuitTxOut> = watchtower_tx
            .input
            .iter()
            .map(|input| {
                let txid = input.previous_output.txid;
                let vout = input.previous_output.vout as usize;

                let tx = all_previous_txs
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

        let watchtower_challenge_witness = CircuitWitness::from(
            watchtower_challenge_tx.input[watchtower_challenge_input_idx as usize]
                .witness
                .clone(),
        );

        for input in &mut watchtower_challenge_tx.input {
            input.witness.clear();
        }

        Ok(Self {
            watchtower_idx,
            watchtower_challenge_input_idx,
            watchtower_challenge_utxos,
            watchtower_challenge_tx,
            watchtower_challenge_witness,
        })
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BridgeCircuitInput {
    pub kickoff_tx: CircuitTransaction, // BridgeCircuitTransaction
    // Add all watchtower pubkeys as global input as Vec<[u8; 32]> Which should be shorter than or equal to 160 elements
    pub all_tweaked_watchtower_pubkeys: Vec<[u8; 32]>, // Per watchtower [u8; 34] or OP_PUSHNUM_1 OP_PUSHBYTES_32 <TweakedXOnlyPublicKey> which is [u8; 32]
    pub watchtower_inputs: Vec<WatchtowerInput>,
    pub hcp: BlockHeaderCircuitOutput,
    pub payout_spv: SPV,
    pub lcp: LightClientProof,
    pub sp: StorageProof,
}

impl BridgeCircuitInput {
    pub fn new(
        kickoff_tx: CircuitTransaction,
        watchtower_inputs: Vec<WatchtowerInput>,
        all_tweaked_watchtower_pubkeys: Vec<[u8; 32]>,
        hcp: BlockHeaderCircuitOutput,
        payout_spv: SPV,
        lcp: LightClientProof,
        sp: StorageProof,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            kickoff_tx,
            watchtower_inputs,
            hcp,
            payout_spv,
            lcp,
            sp,
            all_tweaked_watchtower_pubkeys,
        })
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BridgeCircuitOutput {
    pub winternitz_pubkeys_digest: [u8; 20],
    pub correct_watchtowers: Vec<bool>,
    pub payout_tx_blockhash: [u8; 32],
    pub last_blockhash: [u8; 32],
    pub deposit_txid: [u8; 32],
    pub operator_id: [u8; 32],
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct WatchtowerChallengeSet {
    pub challenge_senders: [u8; 20],
    pub challenge_outputs: Vec<[TxOut; 3]>,
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
