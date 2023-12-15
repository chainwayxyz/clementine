use core::panic::UnwindSafe;

use crypto_bigint::Encoding;
use crypto_bigint::U256;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::btc::calculate_double_sha256;

const MAX_TRANSACTIONS: usize = 4096; // Maximum number of transactions = 2^12 Theoretical limit is approximately 2^16
const MAX_NODES: usize = MAX_TRANSACTIONS * 2; // Maximum number of nodes in the tree
const MAX_DEPTH: u8 = 254; // Maximum depth of the tree

// A simplistic representation of a Merkle tree node

pub type TransactionID = [u8; 32];
pub type HashResult = [u8; 32];

#[derive(Debug, Clone, Copy)]
pub struct Node {
    data: [u8; 32], // Placeholder for the hash
    is_empty: bool,
    level: u8,
}

impl Node {
    fn new(data: [u8; 32], level: u8) -> Self {
        Node { data, is_empty: false , level: level}
    }

    fn empty() -> Self {
        Node { data: [0 as u8; 32], is_empty: true , level: 0}
    }
    pub fn get_data(&self) -> [u8; 32] {
        return self.data;
    }
}


#[derive(Debug, Clone, Copy)]
pub struct MerkleTree {
    depth: u8,
    nodes: [Node; MAX_NODES],
    number_of_transactions: u32,
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
        };

        // Populate leaf nodes
        for (i, &tx) in transactions.iter().enumerate() {
            // let double_hash_of_tx = calculate_double_sha256(&tx);
            // tree.nodes[i] = Node::new(double_hash_of_tx, 0);
            let mut tx_clone = tx.clone();
            tx_clone.reverse();
            tree.nodes[i] = Node::new(tx_clone, 0);
        }

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
                tree.nodes[curr_level_index_offset + i] = Node::new(combined_hash, curr_level_offset as u8);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(&tree.nodes[prev_level_index_offset + prev_level_size - 1].data);
                preimage[32..].copy_from_slice(&tree.nodes[prev_level_index_offset + prev_level_size - 1].data);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_index_offset + (prev_level_size / 2)] = Node::new(combined_hash, curr_level_offset as u8);
            }
            curr_level_offset += 1;
            prev_level_size = (prev_level_size + 1) / 2;
            prev_level_index_offset = curr_level_index_offset;
            curr_level_index_offset += prev_level_size;
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

}

// mod test {

//     use super::*;

//     #[test]
//     fn test_merkle_tree() {
//         let transactions: [[u8; 32]; 5] = [
//             parse_str_to_little_endian_array("29872ac19d9efbcfa619517ffc043713dcded089c0f9994aad91298fc33ca1f9"),
//             parse_str_to_little_endian_array("747e1eb73d9bc7d6d3e109fadf306f75e3285fb5da255508f991052dce4b5b37"),
//             parse_str_to_little_endian_array("6abfac15d53f62ed850ce70879c6bca4460017c7533efc4ed6ea5f2713bdaf5d"),
//             parse_str_to_little_endian_array("c423e4af2a2790f874b2d33be13dd871b969679f6252001cdb840840bfa6d691"),
//             parse_str_to_little_endian_array("c6fb683c9a2390926432de41b0a68bf78ec00696cdba7c082e2d9af2049f7e0e"),
//         ];
//         let merkle_tree = MerkleTree::new(3, &transactions, 5);
//     }

//     #[test]
//     fn test_get_element() {
//         //TODO: create a merkle tree with given tx ids, and then test get_element

//     }
// }

