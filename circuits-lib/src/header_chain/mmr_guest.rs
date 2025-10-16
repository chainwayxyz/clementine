//! # MMR Guest - Merkle Mountain Range for zkVM
//!
//! Lightweight MMR implementation optimized for zero-knowledge virtual machine environments.
//! Stores only subroots and size for efficient proof verification within circuit constraints.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::common::hashes::hash_pair;

use super::mmr_native::MMRInclusionProof;

/// Merkle Mountain Range implementation for zkVM environments.
///
/// Maintains only the essential data (subroots and size) needed for proof verification
/// within the constrained environment of a zero-knowledge proof system.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]

pub struct MMRGuest {
    pub subroots: Vec<[u8; 32]>,
    pub size: u32,
}

impl Default for MMRGuest {
    fn default() -> Self {
        MMRGuest::new()
    }
}

impl MMRGuest {
    /// Creates a new empty MMR instance.
    pub fn new() -> Self {
        MMRGuest {
            subroots: vec![],
            size: 0,
        }
    }

    /// Appends a new leaf to the MMR, updating subroots as needed.
    ///
    /// Implements the MMR append algorithm by combining consecutive pairs
    /// of nodes to maintain the mountain range structure.
    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut current = leaf;
        let mut size = self.size;
        while size % 2 == 1 {
            let sibling = self.subroots.pop().unwrap();
            current = hash_pair(sibling, current);
            size /= 2
        }
        self.subroots.push(current);
        self.size += 1;
    }

    /// Verifies an inclusion proof against the MMR subroots.
    ///
    /// Replays the Merkle path from leaf to subroot and checks if the computed
    /// subroot matches the stored subroot at the specified index.
    pub fn verify_proof(&self, leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool {
        let mut current_hash = leaf;
        for i in 0..mmr_proof.inclusion_proof.len() {
            let sibling = mmr_proof.inclusion_proof[i];
            if mmr_proof.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        self.subroots.get(mmr_proof.subroot_idx) == Some(&current_hash)
    }
}
