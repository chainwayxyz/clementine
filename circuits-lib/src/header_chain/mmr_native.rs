//! # MMR Native - Merkle Mountain Range for Native Environments
//!
//! Full-featured MMR implementation for native (non-zkVM) environments.
//! Provides proof generation capabilities and maintains complete node structure.

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};

use crate::common::hashes::hash_pair;

/// Merkle Mountain Range implementation for native environments.
///
/// Maintains the complete MMR structure with all nodes across all levels,
/// enabling proof generation and full MMR operations outside of zkVM constraints.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRNative {
    pub nodes: Vec<Vec<[u8; 32]>>,
}

impl Default for MMRNative {
    fn default() -> Self {
        MMRNative::new()
    }
}

impl MMRNative {
    /// Creates a new empty MMR instance.
    pub fn new() -> Self {
        MMRNative {
            nodes: vec![vec![]],
        }
    }

    /// Appends a leaf and recalculates the mountain peaks.
    pub fn append(&mut self, leaf: [u8; 32]) {
        self.nodes[0].push(leaf);
        self.recalculate_peaks();
    }

    /// Recalculates MMR peaks after appending new leaves.
    fn recalculate_peaks(&mut self) {
        let depth = self.nodes.len();
        for level in 0..depth - 1 {
            if self.nodes[level].len() % 2 == 1 {
                break;
            } else {
                let node = hash_pair(
                    self.nodes[level][self.nodes[level].len() - 2],
                    self.nodes[level][self.nodes[level].len() - 1],
                );
                self.nodes[level + 1].push(node);
            }
        }
        if self.nodes[depth - 1].len() > 1 {
            let node = hash_pair(self.nodes[depth - 1][0], self.nodes[depth - 1][1]);
            self.nodes.push(vec![node]);
        }
    }

    /// Returns the current MMR subroots (peaks of the mountain range).
    fn get_subroots(&self) -> Vec<[u8; 32]> {
        let mut subroots: Vec<[u8; 32]> = vec![];
        for level in &self.nodes {
            if level.len() % 2 == 1 {
                subroots.push(level[level.len() - 1]);
            }
        }
        subroots.reverse();
        subroots
    }

    /// Generates an inclusion proof for a leaf at the given index.
    ///
    /// Returns both the leaf value and the proof needed to verify its inclusion.
    /// The proof can be verified against the MMR subroots.
    pub fn generate_proof(&self, index: u32) -> Result<([u8; 32], MMRInclusionProof)> {
        if self.nodes[0].is_empty() {
            return Err(eyre!("MMR Native is empty"));
        }
        if self.nodes[0].len() <= index as usize {
            return Err(eyre!(
                "Index out of bounds: {} >= {}",
                index,
                self.nodes[0].len()
            ));
        }

        let mut proof: Vec<[u8; 32]> = vec![];
        let mut current_index = index;
        let mut current_level = 0;
        // Returns the subtree proof for the subroot.
        while !(current_index == self.nodes[current_level].len() as u32 - 1
            && self.nodes[current_level].len() % 2 == 1)
        {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            proof.push(self.nodes[current_level][sibling_index as usize]);
            current_index /= 2;
            current_level += 1;
        }
        let (subroot_idx, internal_idx) = self.get_helpers_from_index(index);
        let mmr_proof = MMRInclusionProof::new(subroot_idx, internal_idx, proof);
        Ok((self.nodes[0][index as usize], mmr_proof))
    }

    /// Determines subroot index and internal position for a given leaf index.
    fn get_helpers_from_index(&self, index: u32) -> (usize, u32) {
        let xor = (self.nodes[0].len() as u32) ^ index;
        let xor_leading_digit = 31 - xor.leading_zeros() as usize;
        let internal_idx = index & ((1 << xor_leading_digit) - 1);
        let leading_zeros_size = 31 - (self.nodes[0].len() as u32).leading_zeros() as usize;
        let mut subtree_idx = 0;
        for i in xor_leading_digit + 1..=leading_zeros_size {
            if self.nodes[0].len() & (1 << i) != 0 {
                subtree_idx += 1;
            }
        }
        (subtree_idx, internal_idx)
    }

    /// Verifies an inclusion proof against the current MMR subroots.
    pub fn verify_proof(&self, leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool {
        let subroot = mmr_proof.get_subroot(leaf);
        let subroots = self.get_subroots();
        subroots[mmr_proof.subroot_idx] == subroot
    }
}

/// Proof of inclusion for an element in the MMR.
///
/// Contains all data needed to verify that a specific leaf exists at a given
/// position within the MMR structure.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRInclusionProof {
    pub subroot_idx: usize,
    pub internal_idx: u32,
    pub inclusion_proof: Vec<[u8; 32]>,
}

impl MMRInclusionProof {
    /// Creates a new inclusion proof.
    pub fn new(subroot_idx: usize, internal_idx: u32, inclusion_proof: Vec<[u8; 32]>) -> Self {
        MMRInclusionProof {
            subroot_idx,
            internal_idx,
            inclusion_proof,
        }
    }

    /// Computes the subroot hash by replaying the Merkle path from the leaf.
    pub fn get_subroot(&self, leaf: [u8; 32]) -> [u8; 32] {
        let mut current_hash = leaf;
        for i in 0..self.inclusion_proof.len() {
            let sibling = self.inclusion_proof[i];
            if self.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        current_hash
    }
}

#[cfg(test)]
mod tests {
    use super::MMRNative;
    use crate::header_chain::mmr_guest::MMRGuest;

    #[test]
    fn test_mmr_native_fail_empty() {
        let mmr = MMRNative::new();
        let result = mmr.generate_proof(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "MMR Native is empty");
    }

    #[test]
    fn test_mmr_native_fail_out_of_bounds() {
        let mut mmr = MMRNative::new();
        mmr.append([0; 32]);
        let result = mmr.generate_proof(1);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Index out of bounds"));
    }

    #[test]
    fn test_mmr_native() {
        let mut mmr = MMRNative::new();
        let mut leaves = vec![];

        for i in 0..42 {
            let leaf = [i as u8; 32];
            leaves.push(leaf);

            mmr.append(leaf);

            for j in 0..=i {
                let (leaf, mmr_proof) = mmr.generate_proof(j).unwrap();
                assert!(mmr.verify_proof(leaf, &mmr_proof));
            }
        }
    }

    #[test]
    fn test_mmr_crosscheck() {
        let mut mmr_native = MMRNative::new();
        let mut mmr_guest = MMRGuest::new();
        let mut leaves = vec![];

        for i in 0..42 {
            let leaf = [i as u8; 32];
            leaves.push(leaf);

            mmr_native.append(leaf);
            mmr_guest.append(leaf);

            let subroots_native = mmr_native.get_subroots();
            let subroots_guest = mmr_guest.subroots.clone();
            assert_eq!(
                subroots_native, subroots_guest,
                "Subroots do not match after adding leaf {i}"
            );

            // let root_native = mmr_native.get_root();
            // let root_guest = mmr_guest.get_root();
            // assert_eq!(
            //     root_native, root_guest,
            //     "Roots do not match after adding leaf {}",
            //     i
            // );

            for j in 0..=i {
                let (leaf, mmr_proof) = mmr_native.generate_proof(j).unwrap();
                assert!(
                    mmr_native.verify_proof(leaf, &mmr_proof),
                    "Failed to verify proof for leaf {j} in native MMR"
                );
                assert!(
                    mmr_guest.verify_proof(leaf, &mmr_proof),
                    "Failed to verify proof for leaf {j} in guest MMR",
                );
            }
        }
    }
}
