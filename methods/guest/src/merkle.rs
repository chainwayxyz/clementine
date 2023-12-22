use bridge_core::btc::calculate_double_sha256;
use risc0_zkvm::guest::env;



pub fn add_to_incremental_merkle_tree(merkle_tree_data: u32, leaf: [u8; 32]) {}

pub fn get_incremental_merkle_tree_root(merkle_tree_data: u32) -> [u8; 32] {
    return [0; 32];
}

pub fn get_incremental_merkle_tree_index(merkle_tree_data: u32) -> u32 {
    return 0;
}
pub fn verify_incremental_merkle_path(merkle_tree_data: u32, index: u32) -> [u8; 32] {
    let leaf = env::read();
    let mut hash: [u8; 32] = leaf;
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
