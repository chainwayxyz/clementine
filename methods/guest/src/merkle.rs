use bridge_core::incremental_merkle::{IncrementalMerkleTree, Data, DEPTH, sha256};
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
    let leaf: Data = env::read();
    let mut hash: Data = leaf;
    let mut i: u32 = index;
    for _ in 0..DEPTH {
        let node: Data = env::read();
        hash = if i % 2 == 0 {sha256(hash, node)} else {sha256(node, hash)};
        i /= 2;
    }
    assert_eq!(merkle_tree_data.root, hash);
    return leaf;
}
