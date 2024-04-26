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
        240, 46, 113, 222, 220, 199, 72, 92, 215, 201, 134, 161, 55, 159, 164, 12, 204, 45, 18,
        104, 6, 128, 245, 179, 50, 80, 93, 74, 246, 165, 14, 118,
    ],
    [
        239, 220, 20, 230, 23, 32, 160, 104, 119, 219, 5, 97, 146, 59, 85, 167, 94, 55, 204, 28,
        162, 62, 188, 18, 36, 214, 20, 142, 51, 46, 207, 114,
    ],
    [
        141, 123, 155, 230, 74, 20, 62, 246, 233, 108, 174, 133, 94, 36, 36, 183, 144, 213, 183,
        90, 207, 74, 237, 237, 202, 99, 231, 11, 94, 42, 133, 54,
    ],
    [
        84, 157, 96, 85, 221, 69, 198, 190, 169, 228, 62, 218, 157, 72, 19, 242, 96, 134, 182, 183,
        233, 25, 150, 14, 104, 65, 96, 98, 85, 89, 114, 191,
    ],
];
/// Block heights at which each period ends
/// After each period_end_block_height, the corresponding connector source utxo opens after K_DEEP + MAX_BITVM_CHALLENGE_RESPONSE blocks.
pub const PERIOD_END_BLOCK_HEIGHTS: [u32; NUM_ROUNDS] = [0; NUM_ROUNDS];
/// Constant bridge amount in sats
pub const BRIDGE_AMOUNT_SATS: u64 = 1_700;
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
