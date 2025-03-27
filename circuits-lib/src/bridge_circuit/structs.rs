use borsh::{BorshDeserialize, BorshSerialize};
use final_spv::spv::SPV;
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

#[derive(Debug, Clone, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct LightClientProof {
    pub lc_journal: Vec<u8>,
    pub l2_height: String,
}

#[derive(Debug, Clone, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StorageProof {
    pub storage_proof_utxo: String, // This will be an Outpoint but only a txid is given
    pub storage_proof_deposit_idx: String, // This is the index of the withdrawal
    pub index: u32,                 // For now this is 18, for a specifix withdrawal
    pub txid_hex: [u8; 32],         // Move txid
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BridgeCircuitInput {
    pub watchtower_challenge_input_idxs: Vec<u8>,
    pub watchtower_challenge_utxos: Vec<Vec<Vec<u8>>>,
    pub watchtower_challenge_txs: Vec<Vec<u8>>,
    pub hcp: BlockHeaderCircuitOutput,
    pub payout_spv: SPV,
    pub lcp: LightClientProof,
    pub sp: StorageProof,
    pub num_watchtowers: u32,
}

impl BridgeCircuitInput {
    pub fn new(
        watchtower_challenge_input_idxs: Vec<u8>,
        watchtower_challenge_utxos: Vec<Vec<Vec<u8>>>,
        watchtower_challenge_txs: Vec<Vec<u8>>,
        hcp: BlockHeaderCircuitOutput,
        payout_spv: SPV,
        lcp: LightClientProof,
        sp: StorageProof,
        num_watchtowers: u32,
    ) -> Result<Self, &'static str> {
        if num_watchtowers > 160 {
            return Err("num_watchtowers exceeds the limit: 160");
        }
        Ok(Self {
            watchtower_challenge_input_idxs,
            watchtower_challenge_utxos,
            watchtower_challenge_txs,
            hcp,
            payout_spv,
            lcp,
            sp,
            num_watchtowers,
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
