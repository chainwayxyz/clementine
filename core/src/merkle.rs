use crypto_bigint::Encoding;
use crypto_bigint::U256;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::btc::calculate_double_sha256;

const MAX_TRANSACTIONS: usize = 4096; // Maximum number of transactions = 2^12 Theoretical limit is approximately 2^16
const MAX_NODES: usize = MAX_TRANSACTIONS * 2; // Maximum number of nodes in the tree
const MAX_DEPTH: u8 = 16; // Maximum depth of the tree

// A simplistic representation of a Merkle tree node

pub type TransactionID = [u8; 32];
pub type HashResult = [u8; 32];

#[derive(Debug, Clone, Copy)]
pub struct Node {
    data: [u8; 32], // Placeholder for the hash
    is_empty: bool,
    level: u8,
    index: u32,
}

impl Node {
    fn new(data: [u8; 32], level: u8, index: u32) -> Self {
        Node { data, is_empty: false , level: level, index: index}
    }

    fn empty() -> Self {
        Node { data: [0 as u8; 32], is_empty: true , level: 0, index: 0}
    }
    pub fn get_data(&self) -> [u8; 32] {
        return self.data;
    }

    pub fn get_index(&self) -> u32 {
        return self.index;
    }
    pub fn get_level(&self) -> u8 {
        return self.level;
    }
}


#[derive(Debug, Clone, Copy)]
pub struct MerkleTree {
    depth: u8,
    nodes: [Node; MAX_NODES],
    number_of_transactions: u32,
    number_of_elems_per_level: [u32; MAX_DEPTH as usize],
}

impl MerkleTree {
    pub fn new(depth: u8, transactions: &[[u8; 32]], number_of_txs: u32) -> Self {
        assert!(depth > 0, "Depth must be greater than 0");
        assert!(depth <= 254, "Depth must be less than or equal to 254");
        assert!(u32::pow(2, (depth) as u32) >= number_of_txs, "Too many transactions for this depth");
        assert!(number_of_txs == transactions.len() as u32, "Number of transactions does not match the length of the transactions array");
        let mut tree = MerkleTree {
            depth: depth,
            nodes: [Node::empty(); MAX_NODES as usize],
            number_of_transactions: number_of_txs,
            number_of_elems_per_level: [0; MAX_DEPTH as usize],
        };

        // Populate leaf nodes
        for (i, &tx) in transactions.iter().enumerate() {
            let mut tx_clone = tx.clone();
            tx_clone.reverse();
            tree.nodes[i] = Node::new(tx_clone, 0, i as u32);
        }
        tree.number_of_elems_per_level[0] = number_of_txs;

        // Construct the tree
        let mut curr_level_offset: u8 = 1;
        let mut prev_level_size = transactions.len();
        let mut prev_level_index_offset = 0;
        let mut curr_level_index_offset = transactions.len();

        while prev_level_size > 1 {
            for i in 0..(prev_level_size / 2) {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(&tree.nodes[prev_level_index_offset + i * 2].data);
                preimage[32..].copy_from_slice(&tree.nodes[prev_level_index_offset + i * 2 + 1].data);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_index_offset + i] = Node::new(combined_hash, curr_level_offset as u8, i as u32);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(&tree.nodes[prev_level_index_offset + prev_level_size - 1].data);
                preimage[32..].copy_from_slice(&tree.nodes[prev_level_index_offset + prev_level_size - 1].data);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_index_offset + (prev_level_size / 2)] = Node::new(combined_hash, curr_level_offset as u8, (prev_level_size / 2) as u32);
            }
            curr_level_offset += 1;
            prev_level_size = (prev_level_size + 1) / 2;
            prev_level_index_offset = curr_level_index_offset;
            curr_level_index_offset += prev_level_size;
            tree.number_of_elems_per_level[curr_level_offset as usize - 1] = prev_level_size as u32;
        }
        tree
    }

    // Returns the Merkle root
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut root_idx = 0;
        let mut no_of_tx = self.number_of_transactions;
        while no_of_tx > 1 {
            root_idx += no_of_tx;
            no_of_tx = (no_of_tx + 1) / 2;
        }
        return self.nodes[root_idx as usize].data;
    }

    pub fn get_root_index(&self) -> u32 {
        let mut root_idx = 0;
        let mut no_of_tx = self.number_of_transactions;
        while no_of_tx > 1 {
            root_idx += no_of_tx;
            no_of_tx = (no_of_tx + 1) / 2;
        }
        return root_idx;
    }

    pub fn get_element(&self, level: u8, index: u32) -> Node {
        let mut no_of_tx = self.number_of_transactions;
        let mut idx = 0;
        let mut i = 0;
        while i < level {
            idx += no_of_tx;
            no_of_tx = (no_of_tx + 1) / 2;
            i += 1;
        }
        return self.nodes[(idx + index) as usize];
    }

    pub fn get_element_from_index(&self, index: u32) -> Node {
        return self.nodes[index as usize];
    }

    pub fn get_no_of_elem_arr(&self) -> [u32; MAX_DEPTH as usize] {
        return self.number_of_elems_per_level;
    }

    pub fn get_tx_id_path(&self, index: u32) -> [Node; MAX_DEPTH as usize] {
        assert!(index < self.number_of_transactions, "Index out of bounds");
        let mut path: [Node; MAX_DEPTH as usize] = [Node::empty(); MAX_DEPTH as usize];
        let mut i = index;
        let mut level: u8 = 0;
        while level < self.depth {
            if i % 2 == 1 {
                path[level as usize] = self.get_element(level, i - 1);
            } else {
                if (self.number_of_elems_per_level[level as usize] - 1) == i {
                    path[level as usize] = self.get_element(level, i);
                } else {
                    path[level as usize] = self.get_element(level, i + 1);
                }
            }
            level += 1;
            i = i / 2;
        }
        return path;
    }

    pub fn calculate_root_with_merkle_proof(&self, tx_id: [u8; 32], merkle_proof: [Node; MAX_DEPTH as usize]) -> [u8; 32] {
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = tx_id.clone();
        let mut level: u8 = 0;
        while level < self.depth {
            if merkle_proof[level as usize].index % 2 == 1 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize].data);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                preimage[..32].copy_from_slice(&merkle_proof[level as usize].data);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
        }
        combined_hash.reverse();
        return combined_hash;
    }

}
