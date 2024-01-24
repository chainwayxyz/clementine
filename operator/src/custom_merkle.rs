use std::hash;
use std::vec;

use circuit_helpers::constant::HASH_FUNCTION_32;
use circuit_helpers::constant::HASH_FUNCTION_64;
use circuit_helpers::constant::HASH_FUNCTION_96;

use crate::utils::get_custom_merkle_indices;
use crate::utils::get_indices;
use crate::utils::get_internal_indices;

#[derive(Debug, Clone)]
pub struct CustomMerkleProofPreimageElement {
    pub children_hash: [u8; 32],
    pub preimage: [u8; 32],
    pub level: u32,
}

#[derive(Debug, Clone)]
pub struct CustomMerkleProofHashElement {
    pub hash: [u8; 32],
    pub level: u32,
}

#[derive(Debug, Clone)]
pub struct CustomMerkleProof {
    pub preimage_elements: Vec<CustomMerkleProofPreimageElement>,
    pub preimage_hash_elements: Vec<CustomMerkleProofHashElement>,
    pub node_hash_elements: Vec<CustomMerkleProofHashElement>,
}

impl CustomMerkleProof {
    pub fn new(
        preimage_inputs: Vec<CustomMerkleProofPreimageElement>,
        preimage_hash_inputs: Vec<CustomMerkleProofHashElement>,
        node_hash_inputs: Vec<CustomMerkleProofHashElement>,
    ) -> Self {
        Self {
            preimage_elements: preimage_inputs,
            preimage_hash_elements: preimage_hash_inputs,
            node_hash_elements: node_hash_inputs,
        }
    }

    pub fn empty() -> Self {
        Self {
            preimage_elements: Vec::new(),
            preimage_hash_elements: Vec::new(),
            node_hash_elements: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CustomMerkleTree {
    depth: u32,
    pub preimage_hashes: Vec<Vec<[u8; 32]>>,
    pub children_hashes: Vec<Vec<[u8; 32]>>,
    pub node_hashes: Vec<Vec<[u8; 32]>>,
    preimages: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

impl CustomMerkleTree {
    pub fn new(depth: u32, preimages: Vec<Vec<[u8; 32]>>) -> Self {
        let mut preimage_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut children_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut node_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        for (i, level) in preimages.iter().rev().enumerate() {
            let mut level_preimage_hashes = Vec::new();
            let mut level_node_hashes = Vec::new();
            let mut level_children_hashes = Vec::new();
            if (level.len() as u32) == 2u32.pow(depth) {
                for elem in level {
                    let preimage_hash = HASH_FUNCTION_64([i as u8; 32], *elem);
                    let hash = HASH_FUNCTION_64([0u8; 32], preimage_hash);
                    level_children_hashes.push([0u8; 32]);
                    level_preimage_hashes.push(preimage_hash);
                    level_node_hashes.push(hash);
                }
            } else {
                for (j, elem) in level.iter().enumerate() {
                    let child0 = node_hashes[node_hashes.len() - 1][2 * j];
                    let child1 = node_hashes[node_hashes.len() - 1][2 * j + 1];
                    let children_hash = HASH_FUNCTION_64(child0, child1);
                    level_children_hashes.push(children_hash);
                    let curr_hash = HASH_FUNCTION_64([i as u8; 32], *elem);
                    level_preimage_hashes.push(curr_hash);
                    let hash = HASH_FUNCTION_64(children_hash, curr_hash);
                    level_node_hashes.push(hash);
                }
            }
            children_hashes.push(level_children_hashes);
            preimage_hashes.push(level_preimage_hashes);
            node_hashes.push(level_node_hashes);
        }
        let root = node_hashes[node_hashes.len() - 1][0];
        Self {
            depth,
            preimage_hashes: preimage_hashes,
            children_hashes: children_hashes,
            node_hashes: node_hashes,
            preimages,
            root: root,
        }
    }

    pub fn generate_proof(&self, no_of_claims: u32) -> CustomMerkleProof {
        if no_of_claims == 0 {
            return CustomMerkleProof {
                preimage_elements: vec![CustomMerkleProofPreimageElement {
                    children_hash: self.children_hashes[self.depth as usize][0],
                    preimage: self.preimages[0][0],
                    level: self.depth,
                }],
                preimage_hash_elements: vec![],
                node_hash_elements: vec![],
            };
        }
        if no_of_claims == 2u32.pow(self.depth) {
            return CustomMerkleProof {
                preimage_elements: vec![],
                preimage_hash_elements: vec![],
                node_hash_elements: vec![CustomMerkleProofHashElement {
                    hash: self.node_hashes[self.depth as usize][0],
                    level: self.depth,
                }],
            };
        }

        let preimage_indices = get_indices(self.depth, no_of_claims);
        let node_hash_indices = get_internal_indices(self.depth, no_of_claims);
        let preimage_hash_indices = get_custom_merkle_indices(self.depth, no_of_claims);

        let mut proof_preimage_inputs = Vec::new();
        for (i, j) in preimage_indices {
            let preimage_elem = CustomMerkleProofPreimageElement {
                children_hash: self.children_hashes[self.depth as usize - i as usize][j as usize],
                preimage: self.preimages[i as usize][j as usize],
                level: self.depth - i,
            };
            proof_preimage_inputs.push(preimage_elem);
        }

        let mut proof_preimage_hash_inputs = Vec::new();
        for (i, j) in preimage_hash_indices {
            let hash_elem = CustomMerkleProofHashElement {
                hash: self.preimage_hashes[i as usize][j as usize],
                level: i,
            };
            proof_preimage_hash_inputs.push(hash_elem);
        }

        let mut proof_hash_inputs = Vec::new();
        for (i, j) in node_hash_indices {
            let hash_elem = CustomMerkleProofHashElement {
                hash: self.node_hashes[self.depth as usize - i as usize][j as usize],
                level: self.depth - i,
            };
            proof_hash_inputs.push(hash_elem);
        }
        let proof = CustomMerkleProof::new(
            proof_preimage_inputs,
            proof_preimage_hash_inputs,
            proof_hash_inputs,
        );
        return proof;
    }

    pub fn verify_proof(&self, proof: CustomMerkleProof, no_of_claims: u32) -> bool {
        if no_of_claims == 0 {
            let res = HASH_FUNCTION_64(
                proof.preimage_elements[0].children_hash,
                HASH_FUNCTION_64([self.depth as u8; 32], proof.preimage_elements[0].preimage),
            );
            return self.root == res;
        }
        if no_of_claims == 2u32.pow(self.depth) {
            return self.root == proof.node_hash_elements[0].hash;
        }
        // // let mut proof_copy = proof.clone();
        // // let internal_indices = get_internal_indices(self.depth, no_of_claims);

        // let mut temp = [0u8; 32];
        // let mut pre_idx = proof.preimage_elements[0].level as usize;
        // let mut hash_idx = proof.node_hash_elements[0].level as usize;

        // while (pre_idx < proof.preimage_elements.len()) || (hash_idx < proof.node_hash_elements.len()) {
        //     temp = HASH_FUNCTION_64(proof.preimage_elements[pre_idx].children_hash, HASH_FUNCTION_32(proof.preimage_elements[pre_idx].preimage));
        //     temp = HASH_FUNCTION_64(proof.node_hash_elements[hash_idx].node_hash, temp);

        // }

        // println!("internal indices: {:?}", internal_indices);
        // let mut internal_hashes = Vec::new();
        // for (i, j) in internal_indices {
        //     internal_hashes.push(self.hashes[self.hashes.len() - i as usize][j as usize]);
        // }
        // // let mut proof_hashes = Vec::new();
        // for (preimage, i, j) in &proof {
        //     // let proof_hash = HASH
        //     assert_eq!(self.preimages[*i][*j], *preimage);
        // }
        // let mut proof_hashes = Vec::new();
        // for (preimage, i, j) in &proof {
        //     if i == &(self.depth as usize) {
        //         let temp = HASH_FUNCTION_32(*preimage);
        //         assert_eq!(temp, self.hashes[self.depth as usize - *i][*j]);
        //         proof_hashes.push(HASH_FUNCTION_32(*preimage));
        //     } else {
        //         let temp = HASH_FUNCTION_96(self.hashes[self.depth as usize - *i - 1][2 * j], self.hashes[self.depth as usize - *i - 1][2 * j + 1], *preimage);
        //         assert_eq!(temp, self.hashes[self.depth as usize - *i][*j]);
        //         proof_hashes.push(HASH_FUNCTION_96(internal_hashes[*i], self.preimages[*i][*j], *preimage));
        //     }
        // }
        let mut power_of_two = 0;
        let mut temp = no_of_claims;
        while temp % 2 == 0 {
            temp /= 2;
            power_of_two += 1;
        }

        assert_eq!(
            power_of_two,
            (self.depth - proof.preimage_hash_elements.len() as u32)
        );

        assert_eq!(
            proof.preimage_elements.len() + proof.node_hash_elements.len(),
            proof.preimage_hash_elements.len() + 1
        );

        let mut temp: [u8; 32];

        let mut pre_idx = 0;
        let mut hash_idx = 0;

        temp = HASH_FUNCTION_64(
            proof.preimage_elements[pre_idx].children_hash,
            HASH_FUNCTION_64([proof.preimage_elements[pre_idx].level as u8; 32], proof.preimage_elements[pre_idx].preimage),
        );
        println!("temp: {:?}", temp);
        pre_idx += 1;
        temp = HASH_FUNCTION_64(proof.node_hash_elements[hash_idx].hash, temp);
        println!("temp: {:?}", temp);
        hash_idx += 1;
        let mut level_idx = 0;
        println!("level_idx: {}", level_idx);

        while level_idx < self.depth - power_of_two - 1{
            println!("level_idx: {}", level_idx);
            println!("pre_idx: {}", pre_idx);
            println!("hash_idx: {}", hash_idx);
            if pre_idx < proof.preimage_elements.len() && level_idx + power_of_two + 1 == proof.preimage_elements[pre_idx].level {
                println!("if");
                temp = HASH_FUNCTION_64(temp, proof.preimage_hash_elements[level_idx as usize].hash);
                temp = HASH_FUNCTION_64(temp, HASH_FUNCTION_64(proof.preimage_elements[pre_idx].children_hash, HASH_FUNCTION_64([proof.preimage_elements[pre_idx].level as u8; 32], proof.preimage_elements[pre_idx].preimage)));
                pre_idx += 1;
            } else {
                println!("else");
                temp = HASH_FUNCTION_64(temp, proof.preimage_hash_elements[level_idx as usize].hash);
                temp = HASH_FUNCTION_64(proof.node_hash_elements[hash_idx].hash, temp);
                hash_idx += 1;
            }
            println!("temp after level complete: {:?}", temp);
            level_idx += 1;
            // println!("level_idx: {}", level_idx);
        }

        println!("level_idx after while: {}", level_idx);
        println!("pre_idx after while: {}", pre_idx);
        println!("hash_idx after while: {}", hash_idx);

        temp = HASH_FUNCTION_64(temp, proof.preimage_hash_elements[level_idx as usize].hash);

        let flag = temp == self.root;

        let mut total_claim = 0;
        for hash_elem in proof.node_hash_elements {
            total_claim += 2u32.pow(hash_elem.level as u32) as u32;
        }
        println!("total claimed: {}", total_claim);

        let mut total_not_claim = 0;
        for preimage_elem in proof.preimage_elements {
            total_not_claim += 2u32.pow(preimage_elem.level as u32) as u32;
        }
        println!("total not claimed: {}", total_not_claim);

        return flag;
    }
}

#[cfg(test)]
mod tests {

    use secp256k1::rand::{rngs::OsRng, Rng};

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
        println!("verify proof_0: {:?}", merkle_tree.verify_proof(proof_0, 0));
        println!("verify proof_1: {:?}", merkle_tree.verify_proof(proof_1, 1));
        println!("verify proof_2: {:?}", merkle_tree.verify_proof(proof_2, 2));
        println!("verify proof_3: {:?}", merkle_tree.verify_proof(proof_3, 3));
        println!("verify proof_4: {:?}", merkle_tree.verify_proof(proof_4, 4));
        println!("verify proof_5: {:?}", merkle_tree.verify_proof(proof_5, 5));
        println!("verify proof_6: {:?}", merkle_tree.verify_proof(proof_6, 6));
        println!("verify proof_7: {:?}", merkle_tree.verify_proof(proof_7, 7));
        println!("verify proof_8: {:?}", merkle_tree.verify_proof(proof_8, 8));
        // let res = merkle_tree.verify_proof(proof_3, 3);
    }

    #[test]
    fn more_test() {
        let mut rng = OsRng;
        let mut preimages: Vec<Vec<[u8; 32]>> = Vec::new();
        for i in 0..10 {
            let mut preimages_level: Vec<[u8; 32]> = Vec::new();
            for _ in 0..2u32.pow(i) {
                preimages_level.push(rng.gen());
            }
            preimages.push(preimages_level);
        }
        // println!("preimages: {:?}", preimages);
        let merkle_tree_4 = CustomMerkleTree::new(4, preimages[..5].to_vec());
        let proof_5 = merkle_tree_4.generate_proof(5);
        println!("verify proof_5: {:?}", merkle_tree_4.verify_proof(proof_5, 5));

        let merkle_tree_7 = CustomMerkleTree::new(7, preimages[..8].to_vec());
        let proof_31 = merkle_tree_7.generate_proof(31);
        println!("verify proof_31: {:?}", merkle_tree_7.verify_proof(proof_31, 31));

    }

}
