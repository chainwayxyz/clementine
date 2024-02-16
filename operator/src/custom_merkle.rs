use std::vec;

use circuit_helpers::constant::HASH_FUNCTION_64;

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
    depth: usize,
    pub preimage_hashes: Vec<Vec<[u8; 32]>>,
    pub children_hashes: Vec<Vec<[u8; 32]>>,
    pub node_hashes: Vec<Vec<[u8; 32]>>,
    preimages: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

impl CustomMerkleTree {
    pub fn new(depth: usize, preimages: Vec<Vec<[u8; 32]>>) -> Self {
        let mut preimage_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut children_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut node_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
        for (i, level) in preimages.iter().rev().enumerate() {
            let mut level_preimage_hashes = Vec::new();
            let mut level_node_hashes = Vec::new();
            let mut level_children_hashes = Vec::new();
            if (level.len() as u32) == 2u32.pow(depth as u32) {
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
                    children_hash: self.children_hashes[self.depth][0],
                    preimage: self.preimages[0][0],
                    level: self.depth,
                }],
                preimage_hash_elements: vec![],
                node_hash_elements: vec![],
            };
        }
        if no_of_claims == 2u32.pow(self.depth as u32) {
            return CustomMerkleProof {
                preimage_elements: vec![],
                preimage_hash_elements: vec![],
                node_hash_elements: vec![CustomMerkleProofHashElement {
                    hash: self.node_hashes[self.depth as usize][0],
                    level: self.depth,
                }],
            };
        }

        let preimage_indices = CustomMerkleTree::get_indices(self.depth, no_of_claims);
        let node_hash_indices = CustomMerkleTree::get_internal_indices(self.depth, no_of_claims);
        let preimage_hash_indices =
            CustomMerkleTree::get_custom_merkle_indices(self.depth, no_of_claims);

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
        if no_of_claims == 2u32.pow(self.depth as u32) {
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
            (self.depth - proof.preimage_hash_elements.len())
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
            HASH_FUNCTION_64(
                [proof.preimage_elements[pre_idx].level as u8; 32],
                proof.preimage_elements[pre_idx].preimage,
            ),
        );
        // println!("temp: {:?}", temp);
        pre_idx += 1;
        temp = HASH_FUNCTION_64(proof.node_hash_elements[hash_idx].hash, temp);
        // println!("temp: {:?}", temp);
        hash_idx += 1;
        let mut level_idx = 0;
        // println!("level_idx: {}", level_idx);

        while level_idx < self.depth - power_of_two - 1 {
            // println!("level_idx: {}", level_idx);
            // println!("pre_idx: {}", pre_idx);
            // println!("hash_idx: {}", hash_idx);
            if pre_idx < proof.preimage_elements.len()
                && level_idx + power_of_two + 1 == proof.preimage_elements[pre_idx].level
            {
                // println!("if");
                temp =
                    HASH_FUNCTION_64(temp, proof.preimage_hash_elements[level_idx as usize].hash);
                temp = HASH_FUNCTION_64(
                    temp,
                    HASH_FUNCTION_64(
                        proof.preimage_elements[pre_idx].children_hash,
                        HASH_FUNCTION_64(
                            [proof.preimage_elements[pre_idx].level as u8; 32],
                            proof.preimage_elements[pre_idx].preimage,
                        ),
                    ),
                );
                pre_idx += 1;
            } else {
                // println!("else");
                temp =
                    HASH_FUNCTION_64(temp, proof.preimage_hash_elements[level_idx as usize].hash);
                temp = HASH_FUNCTION_64(proof.node_hash_elements[hash_idx].hash, temp);
                hash_idx += 1;
            }
            // println!("temp after level complete: {:?}", temp);
            level_idx += 1;
            // println!("level_idx: {}", level_idx);
        }

        // println!("level_idx after while: {}", level_idx);
        // println!("pre_idx after while: {}", pre_idx);
        // println!("hash_idx after while: {}", hash_idx);

        temp = HASH_FUNCTION_64(temp, proof.preimage_hash_elements[level_idx as usize].hash);

        let flag = temp == self.root;

        // let mut total_claim = 0;
        // for hash_elem in proof.node_hash_elements {
        //     total_claim += 2u32.pow(hash_elem.level as u32) as u32;
        // }
        // // println!("total claimed: {}", total_claim);

        // let mut total_not_claim = 0;
        // for preimage_elem in proof.preimage_elements {
        //     total_not_claim += 2u32.pow(preimage_elem.level as u32) as u32;
        // }
        // // println!("total not claimed: {}", total_not_claim);

        return flag;
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
    use super::*;

    #[test]
    fn test_custom_merkle_tree() {
        let mut preimages: Vec<Vec<[u8; 32]>> = Vec::new();
        for i in 0u8..4 {
            let mut preimages_level: Vec<[u8; 32]> = Vec::new();
            let num_nodes = 2u8.pow(i.into());
            for j in 0u8..num_nodes {
                preimages_level.push([num_nodes - 1 + j; 32]);
            }
            preimages.push(preimages_level);
        }
        let merkle_tree = CustomMerkleTree::new(3, preimages);
        for i in 0..9 {
            let proof = merkle_tree.generate_proof(i);
            assert_eq!(merkle_tree.verify_proof(proof, i), true);
        }
    }

    #[test]
    fn more_test() {
        let mut preimages: Vec<Vec<[u8; 32]>> = Vec::new();
        for i in 0..10 {
            let mut preimages_level: Vec<[u8; 32]> = Vec::new();
            let num_nodes = 2u32.pow(i);
            for j in 0..num_nodes {
                preimages_level.push([(num_nodes - 1 + j) as u8; 32]);
            }
            preimages.push(preimages_level);
        }
        // println!("preimages: {:?}", preimages);
        let merkle_tree_4 = CustomMerkleTree::new(4, preimages[..5].to_vec());
        let proof_5 = merkle_tree_4.generate_proof(5);
        assert_eq!(
            merkle_tree_4.verify_proof(proof_5, 5),
            true,
            "Failed to verify proof for 5 with depth 4"
        );

        let merkle_tree_7 = CustomMerkleTree::new(7, preimages[..8].to_vec());
        let proof_31 = merkle_tree_7.generate_proof(31);
        assert_eq!(
            merkle_tree_7.verify_proof(proof_31, 31),
            true,
            "Failed to verify proof for 31 with depth 7"
        );
    }

    #[test]
    fn test_get_indices() {
        let test_cases = vec![
            ((0, 0), vec![(0, 0)]),
            ((0, 1), vec![]),
            ((1, 0), vec![(0, 0)]),
            ((1, 1), vec![(1, 1)]),
            ((1, 2), vec![]),
            ((2, 0), vec![(0, 0)]),
            ((2, 1), vec![(2, 1), (1, 1)]),
            ((2, 2), vec![(1, 1)]),
            ((2, 3), vec![(2, 3)]),
            ((2, 4), vec![]),
            ((3, 0), vec![(0, 0)]),
            ((3, 1), vec![(3, 1), (2, 1), (1, 1)]),
            ((3, 2), vec![(2, 1), (1, 1)]),
            ((3, 3), vec![(3, 3), (1, 1)]),
            ((3, 4), vec![(1, 1)]),
            ((3, 5), vec![(3, 5), (2, 3)]),
            ((3, 6), vec![(2, 3)]),
            ((3, 7), vec![(3, 7)]),
            ((3, 8), vec![]),
        ];

        for ((depth, index), expected) in test_cases {
            let indices = CustomMerkleTree::get_indices(depth, index);
            assert_eq!(
                indices, expected,
                "Failed at get_indices({}, {})",
                depth, index
            );
        }
    }

    #[test]
    fn test_get_internal_indices() {
        let test_cases = vec![
            ((0, 0), vec![]),
            ((0, 1), vec![(0, 0)]),
            ((1, 0), vec![]),
            ((1, 1), vec![(1, 0)]),
            ((1, 2), vec![(0, 0)]),
            ((2, 0), vec![]),
            ((2, 1), vec![(2, 0)]),
            ((2, 2), vec![(1, 0)]),
            ((2, 3), vec![(2, 2), (1, 0)]),
            ((2, 4), vec![(0, 0)]),
            ((3, 0), vec![]),
            ((3, 1), vec![(3, 0)]),
            ((3, 2), vec![(2, 0)]),
            ((3, 3), vec![(3, 2), (2, 0)]),
            ((3, 4), vec![(1, 0)]),
            ((3, 5), vec![(3, 4), (1, 0)]),
            ((3, 6), vec![(2, 2), (1, 0)]),
            ((3, 7), vec![(3, 6), (2, 2), (1, 0)]),
            ((3, 8), vec![(0, 0)]),
        ];

        for ((depth, index), expected) in test_cases {
            let indices = CustomMerkleTree::get_internal_indices(depth, index);
            assert_eq!(
                indices, expected,
                "Failed at get_internal_indices({}, {})",
                depth, index
            );
        }
    }

    #[test]
    fn test_custom_merkle_indices() {
        let test_cases = vec![
            ((0, 0), vec![]),
            ((0, 1), vec![]),
            ((1, 0), vec![]),
            ((1, 1), vec![(1, 0)]),
            ((1, 2), vec![]),
            ((2, 0), vec![]),
            ((2, 1), vec![(1, 0), (2, 0)]),
            ((2, 2), vec![(2, 0)]),
            ((2, 3), vec![(1, 1), (2, 0)]),
            ((2, 4), vec![]),
            ((3, 0), vec![]),
            ((3, 1), vec![(1, 0), (2, 0), (3, 0)]),
            ((3, 2), vec![(2, 0), (3, 0)]),
            ((3, 3), vec![(1, 1), (2, 0), (3, 0)]),
            ((3, 4), vec![(3, 0)]),
            ((3, 5), vec![(1, 2), (2, 1), (3, 0)]),
            ((3, 6), vec![(2, 1), (3, 0)]),
            ((3, 7), vec![(1, 3), (2, 1), (3, 0)]),
            ((3, 8), vec![]),
        ];

        for ((depth, index), expected) in test_cases {
            let indices = CustomMerkleTree::get_custom_merkle_indices(depth, index);
            assert_eq!(
                indices, expected,
                "Failed at get_custom_merkle_indices({}, {})",
                depth, index
            );
        }
    }
}
