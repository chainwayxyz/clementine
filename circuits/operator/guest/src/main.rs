#![no_main]
#![no_std]

use circuit_helpers::bitcoin::{validate_threshold_and_add_work, BlockHeader};
use circuit_helpers::constant::Data;
use circuit_helpers::hashes::calculate_double_sha256;
use circuit_helpers::hashes::calculate_single_sha256;
use circuit_helpers::config::{N, PERIOD3};
use circuit_helpers::incremental_merkle::IncrementalMerkleTree;
use sha2::{Digest, Sha256};


use guest::bitcoin::verify_txid_input;
use guest::bitcoin::verify_txid_merkle_path;
use guest::bitcoin::verify_txid_output_address;
use risc0_zkvm::guest::env;
use crypto_bigint::Encoding;
use crypto_bigint::U256;

risc0_zkvm::guest::entry!(main);

pub fn handle_withdrawals(merkle_tree_data: &mut IncrementalMerkleTree, merkle_root: Data) -> u32 {
    let num_withdrawals: u32 = env::read();
    for _ in 0..num_withdrawals {
        let withdrawal_txid: [u8; 32] = env::read();
        verify_txid_merkle_path(withdrawal_txid, merkle_root.clone());
        let output_address: [u8; 32] = env::read();

        verify_txid_output_address(withdrawal_txid, output_address);
        merkle_tree_data.add(output_address);
    }
    return num_withdrawals;
}

//calculates leaf hash (merkle root) for the preimage inscription taptree
pub fn get_preimage_inscription_script_hash(actor_pk_bytes: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let tap_leaf_str = "TapLeaf";
    let tap_leaf_tag_hash: [u8; 32] = calculate_single_sha256(&tap_leaf_str.as_bytes());
    hasher.update(&tap_leaf_tag_hash);
    hasher.update(&tap_leaf_tag_hash);
    let num_preimages = env::read();
    hasher.update(&[192]);
    let script_length: u8 = 37 + 33 * num_preimages as u8;
    hasher.update(&[script_length]);
    hasher.update(&[32]);
    hasher.update(&actor_pk_bytes);
    hasher.update(&[172, 0, 99]);
    for _ in 0..num_preimages {
        let preimage: [u8; 32] = env::read();
        hasher.update(&[32]);
        hasher.update(&preimage);
    }
    hasher.update(&[104]);
    hasher.finalize().try_into().unwrap()
}

pub fn verify_light_client(
    _block_hash: Data,
    _withdrawal_merkle_root: Data,
    _deposit_merkle_root: Data,
) {
}

pub fn handle_deposits(
    _start_deposit_index: u32,
    num_deposits: u32,
    num_withdrawals: u32,
    deposit_merkle_tree: &mut IncrementalMerkleTree,
    bridge_funds_merkle_tree: &mut IncrementalMerkleTree,
) -> u32 {
    let mut rem_deposits = num_deposits;
    let mut rem_withdrawals = num_withdrawals;
    for _ in 0..num_deposits {
        let deposit_txid: [u8; 32] = env::read();
        deposit_merkle_tree.add(deposit_txid);
        if rem_withdrawals >= rem_deposits {
            // TODO: Change this to use 2 for loops or use num_deposits - i instead of rem_deposits
            rem_withdrawals -= 1;
        } else {
            bridge_funds_merkle_tree.add(deposit_txid);
        }
        rem_deposits -= 1;
    }
    return rem_withdrawals;
}

pub fn handle_moved_bridge_funds(
    bridge_funds_old_merkle_tree: &mut IncrementalMerkleTree,
    bridge_funds_new_merkle_tree: &mut IncrementalMerkleTree,
    bitcoin_merkle_root: Data,
) -> u32 {
    let num_moved_bridge_funds: u32 = env::read();
    for _i in 0..num_moved_bridge_funds {
        

        let move_txid: [u8; 32] = env::read();
        let moved_bridge_funds_txid: [u8; 32] = env::read();
        
        verify_txid_merkle_path(move_txid, bitcoin_merkle_root.clone());

        verify_txid_input(move_txid, moved_bridge_funds_txid);

        bridge_funds_old_merkle_tree.add(moved_bridge_funds_txid);
        bridge_funds_new_merkle_tree.add(move_txid);

    }
    return num_moved_bridge_funds;
}


pub fn main() {
    let deposit_start_index: u32 = env::read();
    let withdrawal_start_index: u32 = env::read();
    let initial_block_hash: [u8; 32] = env::read();
    let initial_work: [u8; 32] = env::read();
    let bridge_funds_start_merkle_root: [u8; 32] = env::read();

    let mut previous_block_hash = initial_block_hash;
    previous_block_hash.reverse();
    let mut work = U256::from_be_bytes(initial_work);

    let mut deposit_merkle_tree: IncrementalMerkleTree = env::read();
    assert_eq!(deposit_start_index, deposit_merkle_tree.index);
    let mut withdrawal_merkle_tree: IncrementalMerkleTree = env::read();
    assert_eq!(withdrawal_start_index, withdrawal_merkle_tree.index);
    let mut bridge_funds_merkle_tree: IncrementalMerkleTree = env::read();
    assert_eq!(
        bridge_funds_start_merkle_root,
        bridge_funds_merkle_tree.root
    );

    let num_withdrawals: u32 = env::read();
    let num_deposits: u32 = env::read();

    let rem_withdrawals = handle_deposits(
        deposit_start_index,
        num_deposits,
        num_withdrawals,
        &mut deposit_merkle_tree,
        &mut bridge_funds_merkle_tree,
    );

    let mut cur_withdrawals: u32 = 0;
    let mut _cur_moved_funds: u32 = 0;

    let bridge_funds_merkle_root = bridge_funds_merkle_tree.root;
    // We don't need bridge_funds_merkle_tree anymore
    // del bridge_funds_merkle_tree;
    let mut bridge_funds_old_merkle_tree = IncrementalMerkleTree::initial();
    let mut bridge_funds_new_merkle_tree = IncrementalMerkleTree::initial();

    let mut _last_unspent_bridge_fund_index: u32 = 0;

    let mut light_client_block_hash: [u8; 32] = [0; 32];
    let mut light_client_pow: U256 = work.clone();

    for height in 0..N {
        let block_header: BlockHeader = env::read();
        assert_eq!(block_header.previous_block_hash, previous_block_hash);
        let data = &block_header.as_bytes();
        let block_hash = calculate_double_sha256(data);
        work = validate_threshold_and_add_work(block_header.clone(), block_hash, work);

        if height == N / 2 { // TODO: Change this to end of period 1
            light_client_block_hash = block_hash; // This is the block hash that the light client will verify
            light_client_pow = work;
        }

        cur_withdrawals += handle_withdrawals(&mut withdrawal_merkle_tree, block_header.merkle_root);
        _cur_moved_funds += handle_moved_bridge_funds(
            &mut bridge_funds_old_merkle_tree,
            &mut bridge_funds_new_merkle_tree,
            block_header.merkle_root,
        );
        previous_block_hash = block_hash;
    }

    for _ in 0..rem_withdrawals {
        let withdrawal_txid: [u8; 32] = env::read(); // TODO: FILL THIS in HOST
        bridge_funds_old_merkle_tree.add(withdrawal_txid);
    }

    assert_eq!(bridge_funds_old_merkle_tree.root, bridge_funds_merkle_root);
    assert_eq!(cur_withdrawals, num_withdrawals);

    let last_finalized_block_hash = previous_block_hash;

    for _ in N..N + PERIOD3 {
        let block_header: BlockHeader = env::read();
        assert_eq!(block_header.previous_block_hash, previous_block_hash);
        let data = &block_header.as_bytes();
        let block_hash = calculate_double_sha256(data);
        work = validate_threshold_and_add_work(block_header, block_hash, work);
        previous_block_hash = block_hash;
    }

    let withdrawal_merkle_root = withdrawal_merkle_tree.root;
    let deposit_merkle_root = deposit_merkle_tree.root;
    let bridge_funds_end_merkle_root = bridge_funds_new_merkle_tree.root;

    let withdrawal_end_index = withdrawal_merkle_tree.index;
    let deposit_end_index = deposit_merkle_tree.index;

    // Verify lightclient
    verify_light_client(
        light_client_block_hash,
        withdrawal_merkle_root,
        deposit_merkle_root,
    );

    // Inputs:
    env::commit(&deposit_start_index);
    env::commit(&withdrawal_start_index);
    env::commit(&initial_block_hash);
    env::commit(&initial_work);
    env::commit(&bridge_funds_start_merkle_root);

    // Outputs:
    env::commit(&deposit_end_index);
    env::commit(&withdrawal_end_index);
    env::commit(&light_client_block_hash);
    env::commit(&light_client_pow.to_be_bytes());
    env::commit(&bridge_funds_end_merkle_root);

    // Outputs that will be checked for longest chain rule
    env::commit(&last_finalized_block_hash);
    env::commit(&work.to_be_bytes());
}
