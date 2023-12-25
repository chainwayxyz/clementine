#![no_main]
#![no_std]

use bridge_core::btc::{calculate_double_sha256, validate_threshold_and_add_work, BlockHeader};
use bridge_core::config::{PERIOD3, N};
use guest::bitcoin::verify_txid_input;
use guest::bitcoin::verify_txid_merkle_path;
use guest::bitcoin::verify_txid_output_address;
use guest::merkle::IncrementalMerkleTree;
use guest::merkle::verify_incremental_merkle_path;
use bridge_core::merkle::Data;
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);
use crypto_bigint::Encoding;
use crypto_bigint::U256;

pub fn handle_withdrawals(mut merkle_tree_data: IncrementalMerkleTree, merkle_root: Data ) {
    let num_withdrawals: u32 = env::read();
    for _ in 0..num_withdrawals {
        let withdrawal_txid: [u8; 32] = env::read();
        verify_txid_merkle_path(withdrawal_txid, merkle_root.clone());
        let output_address: [u8; 32] = env::read();

        verify_txid_output_address(withdrawal_txid, output_address);
        merkle_tree_data.add(output_address);
    }
}

pub fn verify_light_client(block_hash: Data, withdrawal_merkle_root: Data, deposit_merkle_root: Data) {
    
}

pub fn handle_deposits(start_deposit_index: u32, mut deposit_merkle_tree_data: IncrementalMerkleTree, mut bridge_funds_merkle_tree_data: IncrementalMerkleTree) {
    let num_deposits: u32 = env::read();
    for _ in 0..num_deposits {
        let deposit_txid: [u8; 32] = env::read();
        deposit_merkle_tree_data.add(deposit_txid);
        bridge_funds_merkle_tree_data.add(deposit_txid);
    }
}

pub fn handle_moved_bridge_funds(mut bridge_funds_merkle_tree_data: IncrementalMerkleTree, last_unspent_bridge_fund_index: u32, bitcoin_merkle_root: Data ) -> u32 {
    let num_moved_bridge_funds: u32 = env::read();
    for i in 0..num_moved_bridge_funds {
        let moved_bridge_funds_utxo: [u8; 32] = verify_incremental_merkle_path(bridge_funds_merkle_tree_data, last_unspent_bridge_fund_index + i);

        let move_txid = env::read();
        verify_txid_merkle_path(move_txid, bitcoin_merkle_root.clone());

        let new_bridge_funds_utxo = verify_txid_input(move_txid, moved_bridge_funds_utxo);

        bridge_funds_merkle_tree_data.add(new_bridge_funds_utxo);
    }
    return last_unspent_bridge_fund_index + num_moved_bridge_funds;
}

pub fn main() {
    let start_deposit_index: u32 = env::read();
    let start_withdrawal_index: u32 = env::read();
    let initial_block_hash: [u8; 32] = env::read();
    let initial_work: [u8; 32] = env::read();
    let initial_bridge_funds_merkle_root: [u8; 32] = env::read();

    let mut previous_block_hash = initial_block_hash;
    let mut work = U256::from_be_bytes(initial_work);

    // let mut withdrawal_merkle_tree_data: IncrementalMerkleTree = env::read(); // We should check that start_withdrawal_index matches
    // let mut deposit_merkle_tree_data: IncrementalMerkleTree = env::read(); // We should check that start_deposit_index matches
    // let mut bridge_funds_merkle_tree_data: IncrementalMerkleTree = env::read(); // We should check that initial_bridge_funds_merkle_root matches
    let mut withdrawal_merkle_tree_data = IncrementalMerkleTree::initial(); // We should check that start_withdrawal_index matches
    let mut deposit_merkle_tree_data = IncrementalMerkleTree::initial(); // We should check that start_deposit_index matches
    let mut bridge_funds_merkle_tree_data = IncrementalMerkleTree::initial(); // We should check that initial_bridge_funds_merkle_root matches

    handle_deposits(start_deposit_index, deposit_merkle_tree_data, bridge_funds_merkle_tree_data);
    let mut last_unspent_bridge_fund_index: u32 = env::read();

    let mut light_client_block_hash: [u8; 32] = [0; 32];
    let mut light_client_pow: U256 = work.clone();

    for height in 0..N {
        let block_header: BlockHeader = env::read();
        assert_eq!(block_header.previous_block_hash, previous_block_hash);
        let data = &block_header.as_bytes();
        let block_hash = calculate_double_sha256(data);
        work = validate_threshold_and_add_work(block_header.clone(), block_hash, work);

        if height == N / 2 {
            light_client_block_hash = block_hash; // This is the block hash that the light client will verify
            light_client_pow = work;
        }

        handle_withdrawals(withdrawal_merkle_tree_data, block_header.merkle_root);
        last_unspent_bridge_fund_index = handle_moved_bridge_funds(bridge_funds_merkle_tree_data, last_unspent_bridge_fund_index, block_header.merkle_root);

        previous_block_hash = block_hash;
        
    }

    let last_finalized_block_hash = previous_block_hash;

    for _ in N..N + PERIOD3 {
        let block_header: BlockHeader = env::read();
        assert_eq!(block_header.previous_block_hash, previous_block_hash);
        let data = &block_header.as_bytes();
        let block_hash = calculate_double_sha256(data);
        work = validate_threshold_and_add_work(block_header, block_hash, work);
        previous_block_hash = block_hash;
    }


    
    let withdrawal_merkle_root = withdrawal_merkle_tree_data.root;
    let deposit_merkle_root = deposit_merkle_tree_data.root;
    let bridge_funds_merkle_root = bridge_funds_merkle_tree_data.root;

    let withdrawal_last_index = withdrawal_merkle_tree_data.index;
    let deposit_last_index = deposit_merkle_tree_data.index;

    // Verify lightclient
    verify_light_client(light_client_block_hash, withdrawal_merkle_root, deposit_merkle_root);



    // Inputs:
    env::commit(&start_deposit_index);
    env::commit(&start_withdrawal_index);
    env::commit(&initial_block_hash);
    env::commit(&initial_work);
    env::commit(&initial_bridge_funds_merkle_root);


    // Outputs:
    env::commit(&deposit_last_index);
    env::commit(&withdrawal_last_index);
    env::commit(&light_client_block_hash);
    env::commit(&light_client_pow.to_be_bytes());
    env::commit(&bridge_funds_merkle_root);

    // Outputs that will be checked for longest chain rule
    env::commit(&last_finalized_block_hash);
    env::commit(&work.to_be_bytes());
}