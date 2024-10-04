use crypto_bigint::{Encoding, U256};

use crate::{
    bitcoin::{
        read_and_verify_bitcoin_merkle_path, read_preimages_and_calculate_commit_taproot,
        read_tx_and_calculate_txid, validate_threshold_and_add_work, HeaderWithoutPrevBlockHash,
    },
    constants::{
        BLOCKHASH_MERKLE_TREE_DEPTH, BRIDGE_AMOUNT_SATS, CLAIM_MERKLE_TREE_DEPTH,
        MAX_BLOCK_HANDLE_OPS, NUM_ROUNDS, PERIOD_CLAIM_MT_ROOTS, WITHDRAWAL_MERKLE_TREE_DEPTH,
    },
    double_sha256_hash,
    env::Environment,
    incremental_merkle::IncrementalMerkleTree,
    sha256_hash, HashType,
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
    // tracing::debug!(
    //     "READ {:?} blocks from blockhash {:?}, added to imt, total_work: {:?}",
    //     n,
    //     start_prev_block_hash,
    //     total_work
    // );
    (total_work, lc_block_hash, curr_prev_block_hash)
}

/// Read K for K-deep work calculation
/// Read K block headers
/// Returns total work from blockheight N, accumulated up to blockheight N + K
/// Returns blockhash at N + K
pub fn read_blocks_and_calculate_work<E: Environment>(start_prev_block_hash: [u8; 32]) -> U256 {
    let num_blocks = E::read_u32();
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
    // tracing::debug!(
    //     "READ {:?} blocks from blockhash {:?}, total_work: {:?}",
    //     num_blocks,
    //     start_prev_block_hash,
    //     total_work
    // );
    total_work
}

fn read_header_except_prev_blockhash<E: Environment>() -> HeaderWithoutPrevBlockHash {
    let version = E::read_i32();
    let merkle_root = E::read_32bytes();
    let time = E::read_u32();
    let bits = E::read_u32();
    let nonce = E::read_u32();
    (version, merkle_root, time, bits, nonce)
}

pub fn header_chain_proof<E: Environment>() -> (u32, [u8; 32], [u8; 32], [u32; 8]) {
    let is_genesis = E::read_u32();
    let (mut curr_prev_block_hash, method_id, mut total_work) = if is_genesis == 0 {
        let prev_offset = E::read_u32();
        let prev_block_hash = E::read_32bytes();
        let prev_total_work = E::read_32bytes();
        let prev_method_id = E::read_u32x8();

        assert_eq!(prev_offset, 0);

        let mut journal = [0u32; 73];
        journal[0] = prev_offset;
        for i in 0..32 {
            journal[i + 1] = prev_block_hash[i] as u32;
        }
        for i in 0..32 {
            journal[i + 33] = prev_total_work[i] as u32;
        }
        for i in 0..8 {
            journal[i + 65] = prev_method_id[i];
        }
        E::verify(prev_method_id, &journal);

        (prev_block_hash, prev_method_id, U256::from_be_bytes(prev_total_work))
    } else {
        let start_block_hash = E::read_32bytes();
        let method_id = E::read_u32x8();
        (start_block_hash, method_id, U256::ZERO)
    };
    let return_offset = E::read_u32();
    // let prev_receipt = E::read_32bytes();
    let batch_size = E::read_u32();
    // TODO: Requrie offset<batch_size
    // let mut total_work = U256::ZERO; // Change this to previeous work
    // let mut curr_prev_block_hash = start_block_hash;

    let mut to_return_block_hash: [u8; 32] = [0; 32];

    for i in 0..batch_size {
        let header_without_prev_blockhash = read_header_except_prev_blockhash::<E>();
        curr_prev_block_hash =
            calculate_next_block_hash(curr_prev_block_hash, header_without_prev_blockhash);
        total_work = validate_threshold_and_add_work(
            header_without_prev_blockhash.3.to_le_bytes(),
            curr_prev_block_hash,
            total_work,
        );
        if i == batch_size - return_offset - 1 {
            to_return_block_hash = curr_prev_block_hash;
        }
    }
    (
        return_offset,
        to_return_block_hash,
        total_work.to_be_bytes(),
        method_id,
    )
}

fn read_header_except_root_and_calculate_blockhash<E: Environment>(mt_root: HashType) -> [u8; 32] {
    let version = E::read_i32();
    let prev_blockhash = E::read_32bytes();
    let time = E::read_u32();
    let bits = E::read_u32();
    let nonce = E::read_u32();
    double_sha256_hash!(
        &version.to_le_bytes(),
        &prev_blockhash,
        &mt_root,
        &time.to_le_bytes(),
        &bits.to_le_bytes(),
        &nonce.to_le_bytes()
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
    // tracing::debug!("READ merkle_tree_proof of: {:?}", leaf);
    hash
}

/// Reads a withdrawal proof, adds output address to incremental merkle tree
pub fn read_withdrawal_proof<E: Environment>(
    block_mt_root: [u8; 32],
    imt: &mut IncrementalMerkleTree<WITHDRAWAL_MERKLE_TREE_DEPTH>,
) {
    let output_address = E::read_32bytes();
    // tracing::debug!("READ output_address: {:?}", output_address);
    let txid =
        read_tx_and_calculate_txid::<E>(None, Some((Some(BRIDGE_AMOUNT_SATS), output_address)));
    // tracing::debug!("READ tx and calculated txid: {:?}", txid);
    let block_tx_mt_root = read_and_verify_bitcoin_merkle_path::<E>(txid);
    // tracing::debug!(
    //     "READ spv proof and calculated block_tx_mt_root: {:?}",
    //     block_tx_mt_root
    // );
    let calculated_blockhash =
        read_header_except_root_and_calculate_blockhash::<E>(block_tx_mt_root);
    tracing::debug!("calculated_blockhash: {:?}", calculated_blockhash);
    assert_eq!(
        block_mt_root,
        read_merkle_tree_proof::<E, BLOCKHASH_MERKLE_TREE_DEPTH>(calculated_blockhash, None)
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

/// TODO: implement this function
pub fn verify_challenge_proof(_proof: [[u8; 32]; 4]) -> bool {
    true
}

pub fn read_and_verify_verifiers_challenge_proof<E: Environment>() -> (U256, [u8; 32], u8) {
    let mock_proof: [[u8; 32]; 4] = [
        E::read_32bytes(),
        E::read_32bytes(),
        E::read_32bytes(),
        E::read_32bytes(),
    ];
    // tracing::debug!("READ mock_proof: {:?}", mock_proof);
    let lc_cutoff_blockhash = E::read_32bytes();
    // tracing::debug!("READ lc_cutoff_blockhash: {:?}", lc_cutoff_blockhash);
    let max_pow_bytes = E::read_32bytes();
    // tracing::debug!("READ max_pow_bytes: {:?}", max_pow_bytes);
    let period_num = E::read_u32();
    // tracing::debug!("READ period_num: {:?}", period_num);
    let max_pow_u256 = U256::from_le_slice(&max_pow_bytes);
    // tracing::debug!("READ max_pow_u256: {:?}", max_pow_u256);
    assert!(verify_challenge_proof(mock_proof));
    (max_pow_u256, lc_cutoff_blockhash, period_num as u8)
}

pub fn bridge_proof<E: Environment>() -> (U256, [u8; 32], u8) {
    let mut blockhashes_mt = IncrementalMerkleTree::new();
    let mut withdrawal_mt = IncrementalMerkleTree::new();
    let mut total_pow = U256::ZERO;
    let mut cur_block_hash = E::read_32bytes(); // Currently we are reading the first block hash

    // tracing::debug!("READ first_block_hash: {:?}", cur_block_hash);

    let mut lc_blockhash = [0; 32];
    let mut total_num_withdrawals = 0;
    let mut last_period = 0;
    for period_count in 0..NUM_ROUNDS {
        // tracing::debug!("Proving for Period: {}", period_count);

        let work;
        (work, lc_blockhash, cur_block_hash) = read_blocks_and_add_to_merkle_tree::<E>(
            cur_block_hash,
            &mut blockhashes_mt,
            MAX_BLOCK_HANDLE_OPS,
        );

        total_pow = total_pow.wrapping_add(&work);

        let num_withdrawals = E::read_u32();
        // // tracing::debug!("READ num_withdrawals: {:?}", num_withdrawals);
        for _ in 0..num_withdrawals {
            read_withdrawal_proof::<E>(blockhashes_mt.root, &mut withdrawal_mt);
        }
        total_num_withdrawals += num_withdrawals;

        let do_you_want_to_end_proving = E::read_u32();
        if do_you_want_to_end_proving == 1 {
            last_period = period_count;
            break;
        }
        // tracing::debug!("Proving for Period: {}", period_count);
    }

    let (verifiers_pow, verifiers_last_finalized_blockhash, verifiers_challenge_period) =
        read_and_verify_verifiers_challenge_proof::<E>();

    /// TODO: find a way to implement this
    fn win() {
        // tracing::info!("WIN");
        // We will commit the verifier's challenge and return;
        // env.commit( );
        // exit(0);
    }

    let k_deep_work = read_blocks_and_calculate_work::<E>(cur_block_hash);

    total_pow = total_pow.wrapping_add(&k_deep_work);

    if verifiers_challenge_period != last_period as u8 {
        // For this to work, we need to make sure opeator can't use more than K_DEEP blocks
        if total_pow > verifiers_pow {
            win(); // win instantly since the challenge is for wrong period
        } else {
            panic!("Operator can't prove with different last period when periods don't match");
            // We lose by failing to generate a proof
        }
    }
    if verifiers_last_finalized_blockhash != cur_block_hash {
        if total_pow > verifiers_pow {
            win(); // win instantly since the challenge is with wrong private fork, we don't even need to prove our withdrawals etc
        } else {
            panic!("Operator can't come up with different blockhashes"); // We lose by failing to generate a proof
        }
    }
    // Otherwise everyting is correct, challenge is valid, the verifier and operator agreed on last_period and last_finalized_blockhash
    // We need to generate a proof for the last_period proving withdrawals, blockhashes, and the last blockhash

    // tracing::debug!(
    //     "bridge_proof total_num_withdrawals: {:?}",
    //     total_num_withdrawals
    // );

    read_and_verify_lc_proof::<E>(lc_blockhash, withdrawal_mt.root);
    // tracing::info!("READ and verify lc proof");
    let (commit_taproot_addr, claim_proof_tree_leaf) =
        read_preimages_and_calculate_commit_taproot::<E>();
    // tracing::debug!(
    //     "READ preimages and calculate commit taproot: {:?}",
    //     commit_taproot_addr
    // );
    let commit_taproot_txid =
        read_tx_and_calculate_txid::<E>(None, Some((None, commit_taproot_addr)));
    // tracing::debug!("READ tx and calculate txid: {:?}", commit_taproot_txid);
    // tracing::debug!("commit_taproot_txid: {:?}", commit_taproot_txid);
    let vout = E::read_u32(); // TODO: get the vout from reading the prev tx
    let reveal_txid = read_tx_and_calculate_txid::<E>(Some((commit_taproot_txid, vout)), None);
    // tracing::debug!("READ tx and calculate txid: {:?}", reveal_txid);
    tracing::debug!("reveal_txid: {:?}", reveal_txid);
    let calculated_merkle_root = read_and_verify_bitcoin_merkle_path::<E>(reveal_txid);
    // tracing::debug!(
    //     "READ and verify bitcoin merkle path: {:?}",
    //     calculated_merkle_root
    // );
    let calculated_blockhash =
        read_header_except_root_and_calculate_blockhash::<E>(calculated_merkle_root);
    // tracing::debug!("calculated_blockhash: {:?}", calculated_blockhash);

    assert_eq!(
        blockhashes_mt.root,
        read_merkle_tree_proof::<E, BLOCKHASH_MERKLE_TREE_DEPTH>(calculated_blockhash, None)
    );

    // tracing::debug!("claim_proof_tree_leaf: {:?}", claim_proof_tree_leaf);
    // tracing::debug!("total_num_withdrawals: {:?}", total_num_withdrawals);

    tracing::debug!(
        "mt root for challenge period: {:?}",
        PERIOD_CLAIM_MT_ROOTS[verifiers_challenge_period as usize]
    );

    assert_eq!(
        PERIOD_CLAIM_MT_ROOTS[verifiers_challenge_period as usize],
        read_merkle_tree_proof::<E, CLAIM_MERKLE_TREE_DEPTH>(
            claim_proof_tree_leaf,
            Some(total_num_withdrawals),
        )
    );

    (
        verifiers_pow,
        verifiers_last_finalized_blockhash,
        verifiers_challenge_period,
    )
}
