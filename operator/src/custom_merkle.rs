use circuit_helpers::constant::HASH_FUNCTION_96;
use circuit_helpers::constant::HASH_FUNCTION_32;

use crate::utils::get_indices;
use crate::utils::get_internal_indices;
pub type CustomMerkleProof = Vec<([u8; 32], usize, usize)>;

#[derive(Debug, Clone)]
pub struct CustomMerkleTree {
    depth: u32,
    pub hashes: Vec<Vec<[u8; 32]>>,
    preimages: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

impl CustomMerkleTree {
    pub fn new(depth: u32, preimages: Vec<Vec<[u8; 32]>>) -> Self {
        let mut hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        for level in preimages.iter().rev() {
            let mut level_hashes = Vec::new();
            if (level.len() as u32) == 2u32.pow(depth) {
                for elem in level {
                    let hash = HASH_FUNCTION_32(*elem);
                    level_hashes.push(hash);
                }
            }
            else {
                for (i, elem) in level.iter().enumerate() {
                    let child0 = hashes[hashes.len() - 1][2 * i];
                    let child1 = hashes[hashes.len() - 1][2 * i + 1];
                    let hash = HASH_FUNCTION_96(child0, child1, *elem);
                    level_hashes.push(hash);
                }
            }
            hashes.push(level_hashes);
        }
        let root = hashes[hashes.len() - 1][0];
        Self {
            depth,
            hashes: hashes,
            preimages,
            root: root,
        }
    }

    pub fn generate_proof(&self, no_of_claims: u32) -> CustomMerkleProof {
        if no_of_claims == 0 {
            return vec![(self.preimages[0][0], 0, 0)];
        }
        if no_of_claims == 2u32.pow(self.depth) {
            return vec![];
        }
        let indices = get_indices(self.depth, no_of_claims);
        let mut proof = Vec::new();
        for (i, j) in indices {
            proof.push((self.preimages[i as usize][j as usize], i as usize, j as usize));
        }
        return proof;
    }

    pub fn verify_proof(&self, proof: CustomMerkleProof, no_of_claims: u32) -> bool {
        if no_of_claims == 0 {
            return proof == vec![(self.preimages[0][0], 0, 0)];
        }
        if no_of_claims == 2u32.pow(self.depth) {
            return proof == vec![];
        }

        let internal_indices = get_internal_indices(self.depth, no_of_claims);
        println!("internal indices: {:?}", internal_indices);
        let mut internal_hashes = Vec::new();
        for (i, j) in internal_indices {
            internal_hashes.push(self.hashes[self.hashes.len() - i as usize][j as usize]);
        }
        // let mut proof_hashes = Vec::new();
        for (preimage, i, j) in &proof {
            // let proof_hash = HASH
            assert_eq!(self.preimages[*i][*j], *preimage);
        }
        let mut proof_hashes = Vec::new();
        for (preimage, i, j) in &proof {
            if i == &(self.depth as usize) {
                let temp = HASH_FUNCTION_32(*preimage);
                assert_eq!(temp, self.hashes[self.depth as usize - *i][*j]);
                proof_hashes.push(HASH_FUNCTION_32(*preimage));
            } else {
                let temp = HASH_FUNCTION_96(self.hashes[self.depth as usize - *i - 1][2 * j], self.hashes[self.depth as usize - *i - 1][2 * j + 1], *preimage);
                assert_eq!(temp, self.hashes[self.depth as usize - *i][*j]);
                proof_hashes.push(HASH_FUNCTION_96(internal_hashes[*i], self.preimages[*i][*j], *preimage));
            }
        }

        let mut total = 0;
        for (_, i, _) in proof {
            total += 2u32.pow(self.depth - i as u32) as u32;
        }
        println!("total not claimed: {}", total);

        return false;
    }
}

#[cfg(test)]
mod tests { 

    use secp256k1::rand::{rngs::OsRng, Rng};

    use crate::proof;

    use super::*;

    #[test]
    fn test_custom_merkle_tree() {
        let mut rng = OsRng;
        let mut preimages: Vec<Vec<[u8; 32]>> = Vec::new();
        for i in 0..4 {
            let mut preimages_level: Vec<[u8; 32]> = Vec::new();
            for _ in 0..2u32.pow(i) {
                preimages_level.push(rng.gen());
            }
            preimages.push(preimages_level);
        }
        println!("preimages: {:?}", preimages);
        let merkle_tree = CustomMerkleTree::new(3, preimages);
        println!("merkle tree: {:?}", merkle_tree);
        let proof_0 = merkle_tree.generate_proof(0);
        println!("proof 0: {:?}", proof_0);
        let proof_1 = merkle_tree.generate_proof(1);
        println!("proof 1: {:?}", proof_1);
        let proof_2 = merkle_tree.generate_proof(2);
        println!("proof 2: {:?}", proof_2);
        let proof_3 = merkle_tree.generate_proof(3);
        println!("proof 3: {:?}", proof_3);
        let proof_4 = merkle_tree.generate_proof(4);
        println!("proof 4: {:?}", proof_4);
        let proof_5 = merkle_tree.generate_proof(5);
        println!("proof 5: {:?}", proof_5);
        let proof_6 = merkle_tree.generate_proof(6);
        println!("proof 6: {:?}", proof_6);
        let proof_7 = merkle_tree.generate_proof(7);
        println!("proof 7: {:?}", proof_7);
        let proof_8 = merkle_tree.generate_proof(8);
        println!("proof 8: {:?}", proof_8);
        let res = merkle_tree.verify_proof(proof_3, 3);
    }
}
