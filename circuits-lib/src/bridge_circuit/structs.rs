use borsh::{BorshDeserialize, BorshSerialize};
use final_spv::spv::SPV;
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
    pub txid_hex: [u8; 32],         // Move txid
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
    pub kickoff_tx: Vec<u8>,
    pub watchtower_inputs: WatchtowerInputs,
    pub hcp: BlockHeaderCircuitOutput,
    pub payout_spv: SPV,
    pub lcp: LightClientProof,
    pub sp: StorageProof,
}

impl BridgeCircuitInput {
    pub fn new(
        kickoff_tx: Vec<u8>,
        watchtower_inputs: WatchtowerInputs,
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
