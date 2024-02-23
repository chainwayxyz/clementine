use std::vec;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct CustomMerkleProofPreimageElement {
    pub children_hash: [u8; 32],
    pub preimage: [u8; 32],
    pub level: usize,
}

#[derive(Debug, Clone)]
pub struct CustomMerkleProofHashElement {
    pub hash: [u8; 32],
    pub level: usize,
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
    // depth: usize,
    pub preimage_hashes: Vec<Vec<[u8; 32]>>,
    pub children_hashes: Vec<Vec<[u8; 32]>>,
    pub node_hashes: Vec<Vec<[u8; 32]>>,
    // preimages: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

impl CustomMerkleTree {
    pub fn get_claim_proof_tree_leaf(
        depth: usize,
        num_claims: usize,
        connector_tree_hashes: &Vec<Vec<[u8; 32]>>,
    ) -> [u8; 32] {
        let indices = CustomMerkleTree::get_indices(depth, num_claims as u32);
        let mut hasher = Sha256::new();
        indices.iter().for_each(|(level, index)| {
            hasher.update(&connector_tree_hashes[*level][*index]);
        });
        hasher.finalize().try_into().unwrap()
    }
    pub fn calculate_claim_proof_root(
        depth: usize,
        connector_tree_hashes: &Vec<Vec<[u8; 32]>>,
    ) -> [u8; 32] {
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        for i in 0..2u32.pow(depth as u32) {
            let hash = CustomMerkleTree::get_claim_proof_tree_leaf(
                depth,
                i as usize,
                connector_tree_hashes,
            );
            hashes.push(hash);
        }
        let mut level = 0;
        while level < depth {
            let mut level_hashes: Vec<[u8; 32]> = Vec::new();
            for i in 0..2u32.pow(depth as u32 - level as u32 - 1) {
                let mut hasher = Sha256::new();
                hasher.update(&hashes[i as usize * 2]);
                hasher.update(&hashes[i as usize * 2 + 1]);
                let hash = hasher.finalize().try_into().unwrap();
                level_hashes.push(hash);
            }
            hashes = level_hashes.clone();
            level = level + 1;
        }
        hashes[0]
    }

    pub fn get_indices(depth: usize, count: u32) -> Vec<(usize, usize)> {
        assert!(count <= 2u32.pow(depth as u32));

        if count == 0 {
            return vec![(0, 0)];
        }

        let mut indices: Vec<(usize, usize)> = Vec::new();
        if count == 2u32.pow(depth as u32) {
            return indices;
        }

        if count % 2 == 1 {
            indices.push((depth, count as usize));
            indices.extend(CustomMerkleTree::get_indices(depth - 1, (count + 1) / 2));
        } else {
            indices.extend(CustomMerkleTree::get_indices(depth - 1, count / 2));
        }

        return indices;
    }

    pub fn get_internal_indices(depth: usize, count: u32) -> Vec<(usize, usize)> {
        assert!(count <= 2u32.pow(depth as u32));

        if count == 2u32.pow(depth as u32) {
            return vec![(0, 0)];
        }

        let mut indices: Vec<(usize, usize)> = Vec::new();
        if count == 0 {
            return indices;
        }

        if count % 2 == 1 {
            indices.push((depth, count as usize - 1));
            indices.extend(CustomMerkleTree::get_internal_indices(
                depth - 1,
                (count - 1) / 2,
            ));
        } else {
            indices.extend(CustomMerkleTree::get_internal_indices(depth - 1, count / 2));
        }

        return indices;
    }

    pub fn get_custom_merkle_indices(depth: usize, count: u32) -> Vec<(usize, usize)> {
        assert!(count <= 2u32.pow(depth as u32));

        if count == 0 {
            return vec![];
        }

        if count == 2u32.pow(depth as u32) {
            return vec![];
        }

        let mut indices: Vec<(usize, usize)> = Vec::new();
        let mut level = 0;
        let mut index = count;
        while index % 2 == 0 {
            index = index / 2;
            level += 1;
        }

        while level < depth {
            if index % 2 == 1 {
                indices.push((level + 1, (index as usize - 1) / 2));
            } else {
                indices.push((level + 1, index as usize / 2))
            }
            level = level + 1;
            index = index / 2;
        }

        return indices;
    }
}

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_custom_merkle_tree() {
    //     let mut preimages: Vec<Vec<[u8; 32]>> = Vec::new();
    //     for i in 0u8..4 {
    //         let mut preimages_level: Vec<[u8; 32]> = Vec::new();
    //         let num_nodes = 2u8.pow(i.into());
    //         for j in 0u8..num_nodes {
    //             preimages_level.push([num_nodes - 1 + j; 32]);
    //         }
    //         preimages.push(preimages_level);
    //     }
    //     let merkle_tree = CustomMerkleTree::new(3, preimages);
    //     for i in 0..9 {
    //         let proof = merkle_tree.generate_proof(i);
    //         assert_eq!(merkle_tree.verify_proof(proof, i), true);
    //     }
    // }

    // #[test]
    // fn more_test() {
    //     let mut preimages: Vec<Vec<[u8; 32]>> = Vec::new();
    //     for i in 0..10 {
    //         let mut preimages_level: Vec<[u8; 32]> = Vec::new();
    //         let num_nodes = 2u32.pow(i);
    //         for j in 0..num_nodes {
    //             preimages_level.push([(num_nodes - 1 + j) as u8; 32]);
    //         }
    //         preimages.push(preimages_level);
    //     }
    //     // println!("preimages: {:?}", preimages);
    //     let merkle_tree_4 = CustomMerkleTree::new(4, preimages[..5].to_vec());
    //     let proof_5 = merkle_tree_4.generate_proof(5);
    //     assert_eq!(
    //         merkle_tree_4.verify_proof(proof_5, 5),
    //         true,
    //         "Failed to verify proof for 5 with depth 4"
    //     );

    //     let merkle_tree_7 = CustomMerkleTree::new(7, preimages[..8].to_vec());
    //     let proof_31 = merkle_tree_7.generate_proof(31);
    //     assert_eq!(
    //         merkle_tree_7.verify_proof(proof_31, 31),
    //         true,
    //         "Failed to verify proof for 31 with depth 7"
    //     );
    // }

    // #[test]
    // fn test_get_indices() {
    //     let test_cases = vec![
    //         ((0, 0), vec![(0, 0)]),
    //         ((0, 1), vec![]),
    //         ((1, 0), vec![(0, 0)]),
    //         ((1, 1), vec![(1, 1)]),
    //         ((1, 2), vec![]),
    //         ((2, 0), vec![(0, 0)]),
    //         ((2, 1), vec![(2, 1), (1, 1)]),
    //         ((2, 2), vec![(1, 1)]),
    //         ((2, 3), vec![(2, 3)]),
    //         ((2, 4), vec![]),
    //         ((3, 0), vec![(0, 0)]),
    //         ((3, 1), vec![(3, 1), (2, 1), (1, 1)]),
    //         ((3, 2), vec![(2, 1), (1, 1)]),
    //         ((3, 3), vec![(3, 3), (1, 1)]),
    //         ((3, 4), vec![(1, 1)]),
    //         ((3, 5), vec![(3, 5), (2, 3)]),
    //         ((3, 6), vec![(2, 3)]),
    //         ((3, 7), vec![(3, 7)]),
    //         ((3, 8), vec![]),
    //     ];

    //     for ((depth, index), expected) in test_cases {
    //         let indices = CustomMerkleTree::get_indices(depth, index);
    //         assert_eq!(
    //             indices, expected,
    //             "Failed at get_indices({}, {})",
    //             depth, index
    //         );
    //     }
    // }

    // #[test]
    // fn test_get_internal_indices() {
    //     let test_cases = vec![
    //         ((0, 0), vec![]),
    //         ((0, 1), vec![(0, 0)]),
    //         ((1, 0), vec![]),
    //         ((1, 1), vec![(1, 0)]),
    //         ((1, 2), vec![(0, 0)]),
    //         ((2, 0), vec![]),
    //         ((2, 1), vec![(2, 0)]),
    //         ((2, 2), vec![(1, 0)]),
    //         ((2, 3), vec![(2, 2), (1, 0)]),
    //         ((2, 4), vec![(0, 0)]),
    //         ((3, 0), vec![]),
    //         ((3, 1), vec![(3, 0)]),
    //         ((3, 2), vec![(2, 0)]),
    //         ((3, 3), vec![(3, 2), (2, 0)]),
    //         ((3, 4), vec![(1, 0)]),
    //         ((3, 5), vec![(3, 4), (1, 0)]),
    //         ((3, 6), vec![(2, 2), (1, 0)]),
    //         ((3, 7), vec![(3, 6), (2, 2), (1, 0)]),
    //         ((3, 8), vec![(0, 0)]),
    //     ];

    //     for ((depth, index), expected) in test_cases {
    //         let indices = CustomMerkleTree::get_internal_indices(depth, index);
    //         assert_eq!(
    //             indices, expected,
    //             "Failed at get_internal_indices({}, {})",
    //             depth, index
    //         );
    //     }
    // }

    // #[test]
    // fn test_custom_merkle_indices() {
    //     let test_cases = vec![
    //         ((0, 0), vec![]),
    //         ((0, 1), vec![]),
    //         ((1, 0), vec![]),
    //         ((1, 1), vec![(1, 0)]),
    //         ((1, 2), vec![]),
    //         ((2, 0), vec![]),
    //         ((2, 1), vec![(1, 0), (2, 0)]),
    //         ((2, 2), vec![(2, 0)]),
    //         ((2, 3), vec![(1, 1), (2, 0)]),
    //         ((2, 4), vec![]),
    //         ((3, 0), vec![]),
    //         ((3, 1), vec![(1, 0), (2, 0), (3, 0)]),
    //         ((3, 2), vec![(2, 0), (3, 0)]),
    //         ((3, 3), vec![(1, 1), (2, 0), (3, 0)]),
    //         ((3, 4), vec![(3, 0)]),
    //         ((3, 5), vec![(1, 2), (2, 1), (3, 0)]),
    //         ((3, 6), vec![(2, 1), (3, 0)]),
    //         ((3, 7), vec![(1, 3), (2, 1), (3, 0)]),
    //         ((3, 8), vec![]),
    //     ];

    //     for ((depth, index), expected) in test_cases {
    //         let indices = CustomMerkleTree::get_custom_merkle_indices(depth, index);
    //         assert_eq!(
    //             indices, expected,
    //             "Failed at get_custom_merkle_indices({}, {})",
    //             depth, index
    //         );
    //     }
    // }
}
