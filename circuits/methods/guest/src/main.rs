#![no_main]
#![no_std]

use core::num;

use bridge_core::btc::{calculate_double_sha256, validate_threshold_and_add_work, BlockHeader};
use bridge_core::config::{N, PERIOD3};
use bridge_core::incremental_merkle::IncrementalMerkleTree;
use bridge_core::merkle::Data;
use guest::bitcoin::verify_txid_input;
use guest::bitcoin::verify_txid_merkle_path;
use guest::bitcoin::verify_txid_output_address;
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);
use crypto_bigint::Encoding;
use crypto_bigint::U256;

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

pub fn verify_light_client(
    block_hash: Data,
    withdrawal_merkle_root: Data,
    deposit_merkle_root: Data,
) {
}

pub fn handle_deposits(
    start_deposit_index: u32,
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
    for i in 0..num_moved_bridge_funds {
        

        let move_txid: [u8; 32] = env::read();
        let moved_bridge_funds_txid: [u8; 32] = env::read();
        
        verify_txid_merkle_path(move_txid, bitcoin_merkle_root.clone());

        let new_bridge_funds_utxo = verify_txid_input(move_txid, moved_bridge_funds_txid);

        bridge_funds_old_merkle_tree.add(move_txid);
        bridge_funds_new_merkle_tree.add(new_bridge_funds_utxo);
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
    let mut cur_moved_funds: u32 = 0;

    let bridge_funds_merkle_root = bridge_funds_merkle_tree.root;
    // We don't need bridge_funds_merkle_tree anymore
    // del bridge_funds_merkle_tree;
    let mut bridge_funds_old_merkle_tree = IncrementalMerkleTree::initial();
    let mut bridge_funds_new_merkle_tree = IncrementalMerkleTree::initial();

    let mut last_unspent_bridge_fund_index: u32 = 0;

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
        cur_moved_funds += handle_moved_bridge_funds(
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
