// #![no_main]
// #![no_std]
// #![cfg_attr(not(test), no_std, no_main)]

pub mod bitcoin;
pub mod bridge;
pub mod constants;
pub mod env;
pub mod hashes;
pub mod incremental_merkle;

/// Type alias for a Merkle root
pub type MerkleRoot = [u8; 32];
/// Type alias for preimage
pub type PreimageType = [u8; 32];
/// Type alias for hash or digest or 32-byte data
pub type HashType = [u8; 32];
