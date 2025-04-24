use std::ops::{Deref, DerefMut};

use bitcoin::{Amount, ScriptBuf, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};
use final_spv::{spv::SPV, transaction::CircuitTransaction};
use header_chain::header_chain::BlockHeaderCircuitOutput;
use serde::{Deserialize, Serialize};

const NUM_OF_WATCHTOWERS: u8 = 160;

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
        watchtower_challenge_utxos: Vec<CircuitTxOut>,
        watchtower_challenge_tx: CircuitTransaction,
        watchtower_challenge_witness: CircuitWitness,
    ) -> Result<Self, &'static str> {
        if watchtower_idx >= NUM_OF_WATCHTOWERS {
            return Err("Watchtower index out of bounds");
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
pub struct WatchtowerInputs {
    pub watchtower_idxs: Vec<u8>,
    pub watchtower_pubkeys: Vec<Vec<u8>>,
    pub watchtower_challenge_input_idxs: Vec<u8>,
    pub watchtower_challenge_utxos: Vec<Vec<Vec<u8>>>,
    pub watchtower_challenge_txs: Vec<Vec<u8>>,
    pub watchtower_challenge_witnesses: Vec<Vec<u8>>,
}

impl WatchtowerInputs {
    pub fn new(
        watchtower_idxs: Vec<u8>,
        watchtower_pubkeys: Vec<Vec<u8>>,
        watchtower_challenge_input_idxs: Vec<u8>,
        watchtower_challenge_utxos: Vec<Vec<Vec<u8>>>,
        watchtower_challenge_txs: Vec<Vec<u8>>,
        watchtower_challenge_witnesses: Vec<Vec<u8>>,
    ) -> Result<Self, &'static str> {
        for idx in &watchtower_idxs {
            if *idx >= NUM_OF_WATCHTOWERS {
                return Err("watchtower_idx exceeds the number of watchtowers");
            }
        }

        Ok(Self {
            watchtower_idxs,
            watchtower_pubkeys,
            watchtower_challenge_input_idxs,
            watchtower_challenge_utxos,
            watchtower_challenge_txs,
            watchtower_challenge_witnesses,
        })
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BridgeCircuitInput {
    pub kickoff_tx: CircuitTransaction, // BridgeCircuitTransaction
    // Add all watchtower pubkeys as global input as Vec<[u8; 32]> Which should be shorter than or equal to 160 elements
    pub all_watchtower_pubkeys: Vec<Vec<u8>>, // Per watchtower [u8; 34] or OP_PUSHNUM_1 OP_PUSHBYTES_32 <TweakedXOnlyPublicKey> which is [u8; 32]
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
        all_watchtower_pubkeys: Vec<Vec<u8>>,
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
            all_watchtower_pubkeys,
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
