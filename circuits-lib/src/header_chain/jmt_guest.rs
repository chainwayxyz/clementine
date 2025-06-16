use borsh::{BorshDeserialize, BorshSerialize};
use jmt::{proof::{SparseMerkleProof, UpdateMerkleProof}, KeyHash, RootHash};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const DEFAULT_EMPTY_JMT_ROOT_BYTES: [u8; 32] = [
    83, 80, 65, 82, 83, 69, 95, 77, 69, 82, 75, 76, 69, 95, 80, 76, 65, 67, 69,
    72, 79, 76, 68, 69, 82, 95, 72, 65, 83, 72, 95, 95,
];

/// Represents the MMR for inside zkVM (guest)
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]

pub struct JMTGuest {
    pub jmt_root: RootHash,
}

impl JMTGuest {
    pub fn new(jmt_root: RootHash) -> Self {
        JMTGuest { jmt_root }
    }

    pub fn default() -> Self {
        JMTGuest {
            jmt_root: RootHash(DEFAULT_EMPTY_JMT_ROOT_BYTES),
        }
    }

    pub fn verify_update(
        &mut self,
        proof: BlockHashInsertionUpdateProof,
        block_hash: [u8; 32],
        block_height: u32,
    ) {
        proof.verify_update(&mut self.jmt_root, (block_hash, block_height));
    }
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct BlockHashInsertionUpdateProof {
    /// The JMT update proof for this insertion
    pub update_proof: UpdateMerkleProof<Sha256>,
    /// The new JMT root hash after insertion
    pub new_root: RootHash,
}

impl BlockHashInsertionUpdateProof {
    pub fn verify_update(self, prev_root: &mut RootHash, update: ([u8; 32], u32)) {
        let key_hash = KeyHash::with::<sha2::Sha256>(update.0);
        let proof_update = (key_hash, Some(update.1.to_be_bytes()));
        self.update_proof
            .verify_update(*prev_root, self.new_root, &[proof_update])
            .unwrap();
        *prev_root = self.new_root;
    }
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct BlockHashInclusionProof {
    /// The JMT inclusion proof for this block hash
    pub inclusion_proof: SparseMerkleProof<Sha256>,
    pub root: RootHash,
}

impl BlockHashInclusionProof {
    pub fn verify_inclusion(
        &self,
        block_hash: [u8; 32],
        block_height: u32,
    ) -> bool {
        let key_hash = KeyHash::with::<sha2::Sha256>(block_hash);
        self.inclusion_proof
            .verify_existence(self.root, key_hash, block_height.to_be_bytes())
            .is_ok()
    }
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct BlockHashExclusionProof {
    /// The JMT inclusion proof for this block hash
    pub exclusion_proof: SparseMerkleProof<Sha256>,
    pub root: RootHash,
}

impl BlockHashExclusionProof {
    pub fn verify_exclusion(
        &self,
        block_hash: [u8; 32],
    ) -> bool {
        let key_hash = KeyHash::with::<sha2::Sha256>(block_hash);
        self.exclusion_proof
            .verify_nonexistence(self.root, key_hash)
            .is_ok()
    }
}
