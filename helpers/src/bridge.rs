use crypto_bigint::U256;
use sha2::{Digest, Sha256};

use crate::{
    bitcoin::{
        read_and_verify_bitcoin_merkle_path, read_preimages_and_calculate_commit_taproot,
        read_tx_and_calculate_txid, validate_threshold_and_add_work, HeaderWithoutPrevBlockHash,
    },
    constants::{
        BLOCKHASH_MERKLE_TREE_DEPTH, BRIDGE_AMOUNT_SATS, CLAIM_MERKLE_TREE_DEPTH, DUST_VALUE,
        MAX_BLOCK_HANDLE_OPS, NUM_ROUNDS, PERIOD_CLAIM_MT_ROOTS, START_PREV_BLOCKHASH,
        WITHDRAWAL_MERKLE_TREE_DEPTH,
    },
    double_sha256_hash,
    env::Environment,
    incremental_merkle::IncrementalMerkleTree,
    sha256_hash,
};

/// Read N
/// Read N block headers (blockheight 1 to N, inclusive)
/// Adds blockhashes to an incremental merkle tree.
/// Assuming starting from blockheight 1,
/// Returns total work accumulated up to (and including) blockheight N, blockhash at N + 1 - MAX_BLOCK_HANDLE_OPS, blockhash at N + 1
/// Writing block hashes from blockheight 2 to N + 1 to an incremental merkle tree (regenerated ones)
pub fn read_blocks_and_add_to_merkle_tree<E: Environment>(
    start_prev_block_hash: [u8; 32],
    imt: &mut IncrementalMerkleTree<BLOCKHASH_MERKLE_TREE_DEPTH>,
    max_block_handle_ops: u32,
) -> (U256, [u8; 32], [u8; 32]) {
    let n = E::read_u32();
    let mut total_work = U256::ZERO;
    let mut curr_prev_block_hash = start_prev_block_hash;
    let mut lc_block_hash: [u8; 32] = [0; 32];

    for i in 0..n {
        let header_without_prev_blockhash = read_header_except_prev_blockhash::<E>();
        if i == n - max_block_handle_ops {
            lc_block_hash = curr_prev_block_hash;
        }
        curr_prev_block_hash =
            calculate_next_block_hash(curr_prev_block_hash, header_without_prev_blockhash);
        imt.add(curr_prev_block_hash);
        total_work = validate_threshold_and_add_work(
            header_without_prev_blockhash.3.to_le_bytes(),
            curr_prev_block_hash,
            total_work,
        );
    }
    (total_work, lc_block_hash, curr_prev_block_hash)
}

/// Read K for K-deep work calculation
/// Read K block headers
/// Returns total work from blockheight N, accumulated up to blockheight N + K
/// Returns blockhash at N + K
pub fn read_blocks_and_calculate_work<E: Environment>(
    start_prev_block_hash: [u8; 32],
    num_blocks: u32,
) -> U256 {
    let mut total_work = U256::ZERO;
    let mut curr_prev_block_hash = start_prev_block_hash;

    for _ in 0..num_blocks {
        let header_without_prev_blockhash = read_header_except_prev_blockhash::<E>();
        curr_prev_block_hash =
            calculate_next_block_hash(curr_prev_block_hash, header_without_prev_blockhash);
        total_work = validate_threshold_and_add_work(
            header_without_prev_blockhash.3.to_le_bytes(),
            curr_prev_block_hash,
            total_work,
        );
    }
    total_work
}

fn read_header_except_prev_blockhash<E: Environment>() -> HeaderWithoutPrevBlockHash {
    let curr_version = E::read_i32();
    let curr_merkle_root = E::read_32bytes();
    let curr_time = E::read_u32();
    let curr_bits = E::read_u32();
    let curr_nonce = E::read_u32();
    (
        curr_version,
        curr_merkle_root,
        curr_time,
        curr_bits,
        curr_nonce,
    )
}

fn calculate_next_block_hash(
    prev_block_hash: [u8; 32],
    header_without_prev_blockhash: HeaderWithoutPrevBlockHash,
) -> [u8; 32] {
    double_sha256_hash!(
        &header_without_prev_blockhash.0.to_le_bytes(),
        &prev_block_hash,
        &header_without_prev_blockhash.1,
        &header_without_prev_blockhash.2.to_le_bytes(),
        &header_without_prev_blockhash.3.to_le_bytes(),
        &header_without_prev_blockhash.4.to_le_bytes()
    )
}

// Assuming `validate_threshold_and_add_work` is implemented elsewhere.

// Reads a merkle tree proof, adds output address to incremental merkle tree, merkle tree depth is D
pub fn read_merkle_tree_proof<E: Environment, const D: usize>(
    leaf: [u8; 32],
    index: Option<u32>,
) -> [u8; 32] {
    let mut level_idx = index.unwrap_or_else(|| E::read_u32());

    let mut hash = leaf;
    for _ in 0..D {
        let sibling = E::read_32bytes();
        hash = if level_idx % 2 == 0 {
            sha256_hash!(&hash, &sibling)
        } else {
            sha256_hash!(&sibling, &hash)
        };
        level_idx /= 2;
    }

    return hash;
}

/// Reads a withdrawal proof, adds output address to incremental merkle tree
pub fn read_withdrawal_proof<E: Environment>(
    block_mt_root: [u8; 32],
    imt: &mut IncrementalMerkleTree<WITHDRAWAL_MERKLE_TREE_DEPTH>,
) {
    let output_address = E::read_32bytes();
    let txid = read_tx_and_calculate_txid::<E>(None, Some((BRIDGE_AMOUNT_SATS, output_address)));
    let blockhash = read_and_verify_bitcoin_merkle_path::<E>(txid);
    assert_eq!(
        block_mt_root,
        read_merkle_tree_proof::<E, 32>(blockhash, None)
    );
    imt.add(output_address);
}

pub fn read_and_verify_lc_proof<E: Environment>(
    lc_blockhash: [u8; 32],
    withdrawal_mt_root: [u8; 32],
) {
    let read_lc_blockhash = E::read_32bytes();
    assert_eq!(read_lc_blockhash, lc_blockhash);
    let read_withdrawal_mt_root = E::read_32bytes();
    assert_eq!(read_withdrawal_mt_root, withdrawal_mt_root);
    // TODO: Verify the proof
}

pub fn read_and_verify_verifiers_challenge_proof<E: Environment>() -> (U256, [u8; 32], u32) {
    unimplemented!()
}

pub fn bridge_proof<E: Environment>() {
    let mut blockhashes_mt = IncrementalMerkleTree::new();
    let mut withdrawal_mt = IncrementalMerkleTree::new();
    let mut total_pow = U256::ZERO;
    let mut last_block_hash = START_PREV_BLOCKHASH;
    for i in 0..NUM_ROUNDS {
        let (work, lc_blockhash, cur_block_hash) = read_blocks_and_add_to_merkle_tree::<E>(
            last_block_hash,
            &mut blockhashes_mt,
            MAX_BLOCK_HANDLE_OPS,
        );

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
            let commit_taproot_txid =
                read_tx_and_calculate_txid::<E>(None, Some((DUST_VALUE, commit_taproot_addr)));
            let reveal_txid = read_tx_and_calculate_txid::<E>(Some((commit_taproot_txid, 0)), None);
            let blockhash = read_and_verify_bitcoin_merkle_path::<E>(reveal_txid);
            assert_eq!(
                blockhashes_mt.root,
                read_merkle_tree_proof::<E, BLOCKHASH_MERKLE_TREE_DEPTH>(blockhash, None)
            );
            assert_eq!(
                PERIOD_CLAIM_MT_ROOTS[i],
                read_merkle_tree_proof::<E, CLAIM_MERKLE_TREE_DEPTH>(
                    claim_proof_tree_leaf,
                    Some(withdrawal_mt.index)
                )
            );

            let k_deep_work = read_blocks_and_calculate_work::<E>(cur_block_hash, 500);
            total_pow = total_pow.wrapping_add(&k_deep_work);

            let (verifiers_pow, verifiers_last_finalized_bh, _verifiers_last_blockheight) =
                read_and_verify_verifiers_challenge_proof::<E>();

            // if our pow is bigger and we have different last finalized block hash, we win
            // that means verifier can't make a challenge for previous periods
            // verifier should wait K_DEEP blocks to make a challenge to make sure operator
            // can't come up with different blockhashes
            if total_pow > verifiers_pow && cur_block_hash != verifiers_last_finalized_bh {
                return;
            }
            //
        }
        last_block_hash = cur_block_hash;
    }
}
