use lazy_static::lazy_static;

use crate::sha256_hash;

/// Depth of the merkle tree that stores blockhashes
pub const BLOCKHASH_MERKLE_TREE_DEPTH: usize = 32;
/// Depth of the merkle tree that stores withdrawals, should be same with the bridge contract
pub const WITHDRAWAL_MERKLE_TREE_DEPTH: usize = 32;
/// Claim merkle tree depth
pub const CLAIM_MERKLE_TREE_DEPTH: usize = 4;
/// This is a period to handle remaining withdrawals, and inscribe connector tree preimages, 1 week = 7*24*6 = 1008
pub const MAX_BLOCK_HANDLE_OPS: u32 = 3;
/// Number of rounds in the bridge
pub const NUM_ROUNDS: usize = 4;
/// The prev_blockhash of the first block of the bridge (calculation of proof of works starts from here)
pub const START_PREV_BLOCKHASH: [u8; 32] = [0; 32];
/// Merkle tree roots for every period for operator to prove they inscribed correct connector tree preimages
pub const PERIOD_CLAIM_MT_ROOTS: [[u8; 32]; NUM_ROUNDS] = [
    [
        85, 38, 202, 251, 20, 240, 131, 49, 69, 204, 18, 179, 147, 159, 95, 24, 82, 58, 63, 24, 75,
        193, 126, 189, 168, 202, 52, 253, 253, 60, 69, 146,
    ],
    [
        244, 25, 233, 128, 50, 217, 63, 14, 88, 180, 190, 18, 123, 158, 26, 9, 211, 17, 84, 157,
        112, 124, 116, 42, 53, 42, 190, 255, 42, 241, 169, 213,
    ],
    [
        24, 228, 97, 136, 68, 220, 206, 98, 225, 242, 65, 239, 237, 82, 119, 231, 200, 11, 231,
        163, 196, 126, 69, 189, 159, 102, 207, 134, 209, 85, 42, 228,
    ],
    [
        139, 47, 163, 97, 55, 2, 193, 146, 82, 184, 20, 99, 181, 206, 87, 219, 69, 2, 42, 254, 174,
        251, 73, 237, 213, 67, 113, 44, 48, 52, 203, 5,
    ],
];
/// Block heights at which each period ends
/// After each period_end_block_height, the corresponding connector source utxo opens after K_DEEP + MAX_BITVM_CHALLENGE_RESPONSE blocks.
pub const PERIOD_END_BLOCK_HEIGHTS: [u32; NUM_ROUNDS] = [0; NUM_ROUNDS];
/// Constant bridge amount in sats
pub const BRIDGE_AMOUNT_SATS: u64 = 100_000_000;
/// Dust value in sats TODO: Remove the need for this
pub const DUST_VALUE: u64 = 1000;
/// Empty leaf of a merkle tree
pub const EMPTYDATA: [u8; 32] = [
    0xcb, 0x0c, 0x9f, 0x42, 0x64, 0x54, 0x6b, 0x15, 0xbe, 0x98, 0x01, 0xec, 0xb1, 0x1d, 0xf7, 0xe4,
    0x3b, 0xfc, 0x68, 0x41, 0x60, 0x9f, 0xc1, 0xe4, 0xe9, 0xde, 0x5b, 0x3a, 0x59, 0x73, 0xaf, 0x38,
]; // keccak256("CITREA");

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
