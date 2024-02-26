use crypto_bigint::U256;

use crate::{
    bitcoin::{read_and_verify_bitcoin_merkle_path, read_arbitrary_tx_and_calculate_txid},
    config::{BRIDGE_AMOUNT_SATS, DEPTH, NUM_ROUNDS},
    constant::DUST_VALUE,
    env::Environment,
    incremental_merkle::IncrementalMerkleTree,
};

/// Read N
/// Read N block headers
/// adds blockhashes to an incremental merkle tree.
/// returns: total work accumulated, blockhash at N - MAX_BLOCK_HANDLE_OPS, blockhash at N
pub fn read_blocks_and_add_to_merkle_tree<E: Environment>(
    _start_prev_block_hash: [u8; 32],
    _imt: &mut IncrementalMerkleTree<DEPTH>,
) -> (U256, [u8; 32], [u8; 32]) {
    unimplemented!()
}

pub fn read_blocks_and_calculate_work<E: Environment>(_start_prev_block_hash: [u8; 32]) -> U256 {
    unimplemented!()
}

// Reads a merkle tree proof, adds output address to incremental merkle tree, merkle tree depth is D
pub fn read_merkle_tree_proof<E: Environment, const D: usize>(
    _leaf: [u8; 32],
    _index: Option<u32>,
) -> [u8; 32] {
    unimplemented!()
}

/// Reads a withdrawal proof, adds output address to incremental merkle tree
pub fn read_withdrawal_proof<E: Environment>(
    block_mt_root: [u8; 32],
    imt: &mut IncrementalMerkleTree<DEPTH>,
) {
    let output_address = E::read_32bytes();
    let txid =
        read_arbitrary_tx_and_calculate_txid::<E>(None, Some((BRIDGE_AMOUNT_SATS, output_address)));
    let blockhash = read_and_verify_bitcoin_merkle_path::<E>(txid);
    assert_eq!(
        block_mt_root,
        read_merkle_tree_proof::<E, 32>(blockhash, None)
    );
    imt.add(output_address);
}

pub fn read_preimages_and_calculate_commit_taproot<E: Environment>() -> ([u8; 32], [u8; 32]) {
    unimplemented!()
}

pub fn read_and_verify_lc_proof<E: Environment>(
    _lc_blockhash: [u8; 32],
    _withdrawal_mt_root: [u8; 32],
) {
}

pub fn read_and_verify_verifiers_challenge_proof<E: Environment>() -> (U256, [u8; 32], u32) {
    unimplemented!()
}

pub const START_BLOCKHASH: [u8; 32] = [0; 32];
pub const PERIODS_CLAIM_MT_ROOTS: [[u8; 32]; NUM_ROUNDS] = [[0; 32]; NUM_ROUNDS];

pub fn bridge_proof<E: Environment>() {
    let mut blockhashes_mt = IncrementalMerkleTree::new();
    let mut withdrawal_mt = IncrementalMerkleTree::new();
    let mut total_pow = U256::ZERO;
    let mut last_block_hash = START_BLOCKHASH;
    for i in 0..NUM_ROUNDS {
        let (work, lc_blockhash, cur_block_hash) =
            read_blocks_and_add_to_merkle_tree::<E>(last_block_hash, &mut blockhashes_mt);

        total_pow = total_pow.wrapping_add(&work);

        let num_withdrawals = E::read_u32();
        for _ in 0..num_withdrawals {
            read_withdrawal_proof::<E>(blockhashes_mt.root, &mut withdrawal_mt);
        }
        let finish_proof = E::read_u32();
        if finish_proof == 1 {
            read_and_verify_lc_proof::<E>(lc_blockhash, withdrawal_mt.root);
            let (commit_taproot_addr, claim_proof_tree_leaf) =
                read_preimages_and_calculate_commit_taproot::<E>();
            let commit_taproot_txid = read_arbitrary_tx_and_calculate_txid::<E>(
                None,
                Some((DUST_VALUE, commit_taproot_addr)),
            );
            let reveal_txid =
                read_arbitrary_tx_and_calculate_txid::<E>(Some((commit_taproot_txid, 0)), None);
            let blockhash = read_and_verify_bitcoin_merkle_path::<E>(reveal_txid);
            assert_eq!(
                blockhashes_mt.root,
                read_merkle_tree_proof::<E, 32>(blockhash, None)
            );
            assert_eq!(
                PERIODS_CLAIM_MT_ROOTS[i],
                read_merkle_tree_proof::<E, 32>(claim_proof_tree_leaf, Some(withdrawal_mt.index))
            );

            let k_deep_work = read_blocks_and_calculate_work::<E>(cur_block_hash);
            total_pow = total_pow.wrapping_add(&k_deep_work);

            let (verifiers_pow, verifiers_last_finalized_bh, _verifiers_last_blockheight) =
                read_and_verify_verifiers_challenge_proof::<E>();

            // if our pow is bigger and we have different last finalized block hash, we win
            // that means verifier can't make a challenge for previous periods
            if total_pow > verifiers_pow && cur_block_hash != verifiers_last_finalized_bh {
                return;
            }
            //
        }
        last_block_hash = cur_block_hash;
    }
}
