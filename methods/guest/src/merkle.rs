use bridge_core::incremental_merkle::{IncrementalMerkleTree, Data, DEPTH, sha256};
use risc0_zkvm::guest::env;

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
