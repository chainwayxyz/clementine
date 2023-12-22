use bridge_core::{btc::calculate_double_sha256, incremental_merkle::{IncrementalMerkleTree, Data}};
use risc0_zkvm::guest::env;

pub fn add_to_incremental_merkle_tree(mut merkle_tree_data: IncrementalMerkleTree, leaf: Data) {
    merkle_tree_data.add(leaf);
}

pub fn get_incremental_merkle_tree_root(merkle_tree_data: IncrementalMerkleTree) -> Data {
    merkle_tree_data.root
}

pub fn get_incremental_merkle_tree_index(merkle_tree_data: IncrementalMerkleTree) -> u32 {
    merkle_tree_data.index
}

pub fn verify_incremental_merkle_path(merkle_tree_data: IncrementalMerkleTree, index: u32) -> Data {
    let leaf = env::read();
    let mut hash: Data = leaf;
    let mut index: u32 = index;
    let mut levels: u32 = 32;
    for _ in 0..levels {
        let node: [u8; 32] = env::read();
        let mut preimage: [u8; 64] = [0; 64];
        preimage[..32].copy_from_slice(&hash);
        preimage[32..].copy_from_slice(&node);
        hash = calculate_double_sha256(&preimage);
        index = index / 2;
    }
    // assert that merkle root is correct
    // assert_eq!(merkle_tree_data.root, hash);
    return leaf;
}
