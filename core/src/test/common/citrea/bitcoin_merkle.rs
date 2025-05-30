use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinMerkleTree {
    depth: u32,
    nodes: Vec<Vec<[u8; 32]>>,
}

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

impl BitcoinMerkleTree {
    pub fn new(transactions: Vec<[u8; 32]>) -> Self {
        // assert!(depth > 0, "Depth must be greater than 0");
        // assert!(depth <= 254, "Depth must be less than or equal to 254");
        // assert!(
        //     u32::pow(2, (depth) as u32) >= transactions.len() as u32,
        //     "Too many transactions for this depth"
        // );
        let depth = (transactions.len() - 1).ilog(2) + 1;
        let mut tree = BitcoinMerkleTree {
            depth,
            nodes: vec![],
        };

        // Populate leaf nodes
        tree.nodes.push(vec![]);
        for tx in transactions.iter() {
            tree.nodes[0].push(*tx);
        }

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = transactions.len();
        let mut prev_level_index_offset = 0;
        let mut preimage: [u8; 64] = [0; 64];
        while prev_level_size > 1 {
            // println!("curr_level_offset: {}", curr_level_offset);
            // println!("prev_level_size: {}", prev_level_size);
            // println!("prev_level_index_offset: {}", prev_level_index_offset);
            tree.nodes.push(vec![]);
            for i in 0..(prev_level_size / 2) {
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1_usize][prev_level_index_offset + i * 2],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2 + 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            curr_level_offset += 1;
            prev_level_size = prev_level_size.div_ceil(2);
            prev_level_index_offset = 0;
        }
        tree
    }

    // Returns the Merkle root
    pub fn root(&self) -> [u8; 32] {
        self.nodes[self.nodes.len() - 1][0]
    }

    pub fn _get_element(&self, level: u32, index: u32) -> [u8; 32] {
        self.nodes[level as usize][index as usize]
    }

    pub fn get_idx_path(&self, index: u32) -> Vec<[u8; 32]> {
        assert!(index < self.nodes[0].len() as u32, "Index out of bounds");
        let mut path = vec![];
        let mut level = 0;
        let mut i = index;
        while level < self.nodes.len() as u32 - 1 {
            if i % 2 == 1 {
                path.push(self.nodes[level as usize][i as usize - 1]);
            } else if (self.nodes[level as usize].len() - 1) as u32 == i {
                path.push(self.nodes[level as usize][i as usize]);
            } else {
                path.push(self.nodes[level as usize][(i + 1) as usize]);
            }

            level += 1;
            i /= 2;
        }

        path
    }

    // pub fn verify_tx_merkle_proof(&self, idx: u32, merkle_proof: Vec<[u8; 32]>) {
    //     let tx_id = self.nodes[0][idx as usize];
    //     let mut preimage: [u8; 64] = [0; 64];
    //     let mut combined_hash: [u8; 32] = tx_id.clone();
    //     let mut index = idx;
    //     let mut level: u32 = 0;
    //     while level < self.depth {
    //         if index % 2 == 0 {
    //             preimage[..32].copy_from_slice(&combined_hash);
    //             preimage[32..].copy_from_slice(&merkle_proof[level as usize]);
    //             combined_hash = calculate_double_sha256(&preimage);
    //         } else {
    //             preimage[..32].copy_from_slice(&merkle_proof[level as usize]);
    //             preimage[32..].copy_from_slice(&combined_hash);
    //             combined_hash = calculate_double_sha256(&preimage);
    //         }
    //         level += 1;
    //         index = index / 2;
    //     }
    //     assert_eq!(combined_hash, self.root());
    // }

    pub fn calculate_root_with_merkle_proof(
        &self,
        txid: [u8; 32],
        idx: u32,
        merkle_proof: Vec<[u8; 32]>,
    ) -> [u8; 32] {
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = txid;
        let mut index = idx;
        let mut level: u32 = 0;
        while level < self.depth {
            if index % 2 == 0 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize]);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                preimage[..32].copy_from_slice(&merkle_proof[level as usize]);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
            index /= 2;
        }
        combined_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let mut transactions: Vec<[u8; 32]> = vec![];
        for i in 0u8..10u8 {
            let tx = [i; 32];
            transactions.push(tx);
        }
        let tree = BitcoinMerkleTree::new(transactions.clone());
        let root = tree.root();
        let idx_path = tree.get_idx_path(0);
        let calculated_root = tree.calculate_root_with_merkle_proof(transactions[0], 0, idx_path);
        assert_eq!(root, calculated_root);
    }
}
