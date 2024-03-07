use lazy_static::lazy_static;

use crate::sha256_hash;

/// Depth of the merkle tree that stores blockhashes
pub const BLOCKHASH_MERKLE_TREE_DEPTH: usize = 32;
/// Depth of the merkle tree that stores withdrawals, should be same with the bridge contract
pub const WITHDRAWAL_MERKLE_TREE_DEPTH: usize = 32;
/// Claim merkle tree depth
pub const CLAIM_MERKLE_TREE_DEPTH: usize = 4;
/// This is a period to handle remaining withdrawals, and inscribe connector tree preimages, 1 week = 7*24*6 = 1008
pub const MAX_BLOCK_HANDLE_OPS: u32 = 1008;
/// Number of rounds in the bridge
pub const NUM_ROUNDS: usize = 4;
/// The prev_blockhash of the first block of the bridge (calculation of proof of works starts from here)
pub const START_BLOCKHASH: [u8; 32] = [0; 32];
/// Merkle tree roots for every period for operator to prove they inscribed correct connector tree preimages
pub const PERIOD_CLAIM_MT_ROOTS: [[u8; 32]; NUM_ROUNDS] = [[0; 32]; NUM_ROUNDS];
/// Block heights at which each period ends
/// After each period_end_block_height, the corresponding connector source utxo opens after K_DEEP + MAX_BITVM_CHALLENGE_RESPONSE blocks.
pub const PERIOD_END_BLOCK_HEIGHTS: [u32; NUM_ROUNDS] = [0; NUM_ROUNDS];
/// Constant bridge amount in sats
pub const BRIDGE_AMOUNT_SATS: u64 = 100_000_000;
/// Dust value in sats TODO: Remove the need for this
pub const DUST_VALUE: u64 = 1000;
/// Empty leaf of a merkle tree
pub const EMPTYDATA: [u8; 32] = [0u8; 32];

lazy_static! {
    /// Zero subtree hashes
    pub static ref ZEROES: [[u8; 32]; WITHDRAWAL_MERKLE_TREE_DEPTH + 1] = {
        let mut a = [EMPTYDATA; WITHDRAWAL_MERKLE_TREE_DEPTH + 1];
        for i in 0..WITHDRAWAL_MERKLE_TREE_DEPTH {
            a[i + 1] = sha256_hash!(a[i], a[i]);
        }
        a
    };
}
