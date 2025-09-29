//! # Circuits-lib - Header Chain Circuit
//! This module contains the implementation of the header chain circuit, which is basically
//! the Bitcoin header chain verification logic.
//!
//! Implementation of this module is inspired by the Bitcoin Core source code and from here:
//! https://github.com/ZeroSync/header_chain/tree/master/program/src/block_header.
//!
//! **⚠️ Warning:** This implementation is not a word-to-word translation of the Bitcoin Core source code.

use bitcoin::{
    block::{Header, Version},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto_bigint::{Encoding, U256};
use mmr_guest::MMRGuest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

use crate::common::{get_network, zkvm::ZkvmGuest};

pub mod mmr_guest;
pub mod mmr_native;

/// The main entry point of the header chain circuit.
///
/// This function implements Bitcoin header chain verification logic within a zero-knowledge
/// virtual machine (zkVM) environment. It processes block headers, verifies chain continuity,
/// validates proof of work, and maintains the chain state.
///
/// ## Verification Process
///
/// The circuit performs several critical validations:
/// - **Method ID Consistency**: Ensures the input `method_id` matches any previous proof's `method_id`
/// - **Chain Continuity**: Confirms each block's `prev_block_hash` matches the `best_block_hash` of the preceding state
/// - **Block Hash Validity**: Calculates double SHA256 hash and checks it's ≤ current difficulty target
/// - **Difficulty Target Validation**: Verifies the `bits` field matches expected difficulty for current network/epoch
/// - **Timestamp Validation**: Ensures block timestamp > median of previous 11 block timestamps
/// - **MMR Integrity**: Maintains Merkle Mountain Range for efficient block hash storage and verification
///
/// ## Parameters
///
/// * `guest` - ZkvmGuest implementation for reading input, verifying proofs, and committing output
///
/// ## Input Format
///
/// Expects `HeaderChainCircuitInput` containing:
/// - `method_id`: Circuit version identifier
/// - `prev_proof`: Either genesis state or previous circuit output
/// - `block_headers`: Vector of block headers to process
///
/// ## Output Format
///
/// Commits `BlockHeaderCircuitOutput` containing:
/// - `method_id`: Same as input for consistency
/// - `genesis_state_hash`: Hash of initial chain state
/// - `chain_state`: Updated chain state after processing all headers
///
/// ## Panics
///
/// The function will panic on any validation failure including:
/// - Method ID mismatch between input and previous proof
/// - Invalid block hash (doesn't meet difficulty target)
/// - Chain discontinuity (prev_block_hash mismatch)
/// - Invalid timestamps
/// - Incorrect difficulty bits
pub fn header_chain_circuit(guest: &impl ZkvmGuest) {
    // Read the input from the host
    let input: HeaderChainCircuitInput = guest.read_from_host();
    let genesis_state_hash: [u8; 32];
    let mut chain_state = match input.prev_proof {
        HeaderChainPrevProofType::GenesisBlock(genesis_state) => {
            genesis_state_hash = genesis_state.to_hash();
            genesis_state
        }
        HeaderChainPrevProofType::PrevProof(prev_proof) => {
            assert_eq!(prev_proof.method_id, input.method_id, "Method ID mismatch, the input method ID must match the previous proof's method ID to ensure the same circuit is always used. Previous proof method ID: {:?}, input method ID: {:?}", prev_proof.method_id, input.method_id);
            guest.verify(input.method_id, &prev_proof);
            genesis_state_hash = prev_proof.genesis_state_hash;
            prev_proof.chain_state
        }
    };

    // Apply the block headers to the chain state
    chain_state.apply_block_headers(input.block_headers);

    // Commit the output to the host
    guest.commit(&BlockHeaderCircuitOutput {
        method_id: input.method_id,
        genesis_state_hash,
        chain_state,
    });
}

/// Network configuration holder for Bitcoin-specific constants.
///
/// Contains different representations of the maximum target for various Bitcoin networks
/// (mainnet, testnet4, signet, regtest). The maximum target defines the lowest possible
/// difficulty for the network.
///
/// ## Fields
///
/// * `max_bits` - Compact representation of maximum target (difficulty bits format)
/// * `max_target` - 256-bit representation of maximum target
/// * `max_target_bytes` - 32-byte array representation of maximum target
///
/// All three fields represent the same value in different formats for computational efficiency.
#[derive(Debug)]
pub struct NetworkConstants {
    pub max_bits: u32,
    pub max_target: U256,
    pub max_target_bytes: [u8; 32],
}

pub const NETWORK_TYPE: &str = get_network();

// Const evaluation of network type from environment
const IS_REGTEST: bool = matches!(NETWORK_TYPE.as_bytes(), b"regtest");
const IS_TESTNET4: bool = matches!(NETWORK_TYPE.as_bytes(), b"testnet4");
const MINIMUM_WORK_TESTNET: U256 =
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000100010001");

/// Network constants for the Bitcoin network configuration.
///
/// Determines the maximum target and difficulty bits based on the `BITCOIN_NETWORK`
/// environment variable. Supports mainnet, testnet4, signet, and regtest networks.
///
/// ## Network-Specific Values
///
/// - **Mainnet/Testnet4**: `max_bits = 0x1D00FFFF` (standard Bitcoin difficulty)
/// - **Signet**: `max_bits = 0x1E0377AE` (custom signet difficulty)
/// - **Regtest**: `max_bits = 0x207FFFFF` (minimal difficulty for testing)
///
/// Defaults to mainnet configuration if no environment variable is set.
pub const NETWORK_CONSTANTS: NetworkConstants = {
    match option_env!("BITCOIN_NETWORK") {
        Some(n) if matches!(n.as_bytes(), b"signet") => NetworkConstants {
            max_bits: 0x1E0377AE,
            max_target: U256::from_be_hex(
                "00000377AE000000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 3, 119, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        },
        Some(n) if matches!(n.as_bytes(), b"regtest") => NetworkConstants {
            max_bits: 0x207FFFFF,
            max_target: U256::from_be_hex(
                "7FFFFF0000000000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                127, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        },
        Some(n) if matches!(n.as_bytes(), b"testnet4") => NetworkConstants {
            max_bits: 0x1D00FFFF,
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        },
        Some(n) if matches!(n.as_bytes(), b"mainnet") => NetworkConstants {
            max_bits: 0x1D00FFFF,
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        },
        // Default to mainnet for None
        None => NetworkConstants {
            max_bits: 0x1D00FFFF,
            max_target: U256::from_be_hex(
                "00000000FFFF0000000000000000000000000000000000000000000000000000",
            ),
            max_target_bytes: [
                0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        },
        _ => panic!("Unsupported network"),
    }
};

/// Expected duration of a difficulty adjustment epoch in seconds.
///
/// Bitcoin adjusts difficulty every 2016 blocks (approximately 2 weeks).
/// - **Standard networks**: 2 weeks = 60 * 60 * 24 * 14 = 1,209,600 seconds
/// - **Custom signet**: Uses 10-second block time, so 60 * 24 * 14 = 20,160 seconds
///
/// See: <https://github.com/chainwayxyz/bitcoin/releases/tag/v29-ten-secs-blocktime-tag>
const EXPECTED_EPOCH_TIMESPAN: u32 = match option_env!("BITCOIN_NETWORK") {
    Some(n) if matches!(n.as_bytes(), b"signet") => 60 * 24 * 14,
    _ => 60 * 60 * 24 * 14,
};

/// Number of blocks in a difficulty adjustment epoch.
///
/// Bitcoin recalculates the difficulty target every 2016 blocks based on the time
/// it took to mine those blocks compared to the expected timespan.
const BLOCKS_PER_EPOCH: u32 = 2016;

/// Serializable representation of a Bitcoin block header.
///
/// Contains all fields from the Bitcoin block header in a format suitable for
/// zero-knowledge circuits. This struct can be serialized/deserialized and
/// converted to/from the standard `bitcoin::block::Header` type.
///
/// ## Fields
///
/// * `version` - Block version indicating which validation rules to use
/// * `prev_block_hash` - Hash of the previous block in the chain (32 bytes)
/// * `merkle_root` - Merkle tree root of all transactions in the block (32 bytes)
/// * `time` - Block timestamp as Unix time
/// * `bits` - Compact representation of the difficulty target
/// * `nonce` - Counter used in proof-of-work mining
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct CircuitBlockHeader {
    pub version: i32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl CircuitBlockHeader {
    /// Computes the double SHA256 hash of the block header.
    ///
    /// This implements Bitcoin's block hashing algorithm:
    /// 1. Serialize header fields in little-endian format
    /// 2. Compute SHA256 hash of the serialized data
    /// 3. Compute SHA256 hash of the result from step 2
    ///
    /// ## Returns
    ///
    /// * `[u8; 32]` - The double SHA256 hash of the block header
    pub fn compute_block_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.prev_block_hash);
        hasher.update(self.merkle_root);
        hasher.update(self.time.to_le_bytes());
        hasher.update(self.bits.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        let first_hash_result = hasher.finalize_reset();

        hasher.update(first_hash_result);
        let result: [u8; 32] = hasher.finalize().into();
        result
    }
}

impl From<Header> for CircuitBlockHeader {
    fn from(header: Header) -> Self {
        CircuitBlockHeader {
            version: header.version.to_consensus(),
            prev_block_hash: header.prev_blockhash.to_byte_array(),
            merkle_root: header.merkle_root.as_raw_hash().to_byte_array(),
            time: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
        }
    }
}

impl From<CircuitBlockHeader> for Header {
    fn from(val: CircuitBlockHeader) -> Self {
        Header {
            version: Version::from_consensus(val.version),
            prev_blockhash: BlockHash::from_slice(&val.prev_block_hash)
                .expect("Previous block hash is 32 bytes"),
            merkle_root: TxMerkleNode::from_slice(&val.merkle_root)
                .expect("Merkle root is 32 bytes"),
            time: val.time,
            bits: CompactTarget::from_consensus(val.bits),
            nonce: val.nonce,
        }
    }
}

/// Verifiable state of the Bitcoin header chain.
///
/// Maintains all information necessary to verify the next block in the chain,
/// including difficulty adjustment state, timestamp validation data, and an MMR
/// for efficient block hash storage and verification.
///
/// ## Fields
///
/// * `block_height` - Current height of the chain (u32::MAX for uninitialized state)
/// * `total_work` - Cumulative proof-of-work as 32-byte big-endian integer
/// * `best_block_hash` - Hash of the most recently validated block
/// * `current_target_bits` - Current difficulty target in compact representation
/// * `epoch_start_time` - Timestamp of first block in current difficulty epoch
/// * `prev_11_timestamps` - Previous 11 block timestamps for median calculation
/// * `block_hashes_mmr` - Merkle Mountain Range storing subroots
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct ChainState {
    pub block_height: u32,
    pub total_work: [u8; 32],
    pub best_block_hash: [u8; 32],
    pub current_target_bits: u32,
    pub epoch_start_time: u32,
    pub prev_11_timestamps: [u32; 11],
    pub block_hashes_mmr: MMRGuest,
}

impl Default for ChainState {
    fn default() -> Self {
        ChainState::new()
    }
}

impl ChainState {
    /// Creates a new chain state with default values.
    pub fn new() -> Self {
        ChainState {
            block_height: u32::MAX,
            total_work: [0u8; 32],
            best_block_hash: [0u8; 32],
            current_target_bits: NETWORK_CONSTANTS.max_bits,
            epoch_start_time: 0,
            prev_11_timestamps: [0u32; 11],
            block_hashes_mmr: MMRGuest::new(),
        }
    }

    /// Creates a genesis chain state.
    ///
    /// Equivalent to `new()` but with clearer semantic meaning for genesis block scenarios.
    ///
    /// ## Returns
    ///
    /// * `Self` - A new genesis `ChainState`
    pub fn genesis_state() -> Self {
        Self::new()
    }

    /// Computes a cryptographic hash of the current chain state.
    ///
    /// Creates a deterministic hash that uniquely identifies this chain state by
    /// hashing all relevant fields including block height, total work, best block hash,
    /// difficulty parameters, timestamps, and MMR state.
    ///
    /// ## Returns
    ///
    /// * `[u8; 32]` - SHA256 hash uniquely identifying this chain state
    pub fn to_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.block_height.to_le_bytes());
        hasher.update(self.total_work);
        hasher.update(self.best_block_hash);
        hasher.update(self.current_target_bits.to_le_bytes());
        hasher.update(self.epoch_start_time.to_le_bytes());
        for timestamp in self.prev_11_timestamps {
            hasher.update(timestamp.to_le_bytes());
        }
        for hash in self.block_hashes_mmr.subroots.clone() {
            hasher.update(hash);
        }
        hasher.update(self.block_hashes_mmr.size.to_le_bytes());
        hasher.finalize().into()
    }

    /// Applies a sequence of block headers to the chain state.
    ///
    /// Processes each block header in order, performing comprehensive validation
    /// and updating the chain state accordingly. This is the core validation logic
    /// that ensures Bitcoin consensus rules are followed.
    ///
    /// ## Validation Steps (per block header)
    ///
    /// 1. **Chain Continuity**: Verifies `prev_block_hash` matches current `best_block_hash`
    /// 2. **Difficulty Validation**: Ensures `bits` field matches expected difficulty
    /// 3. **Proof of Work**: Validates block hash meets the difficulty target
    /// 4. **Timestamp Validation**: Checks timestamp > median of last 11 timestamps
    /// 5. **State Updates**: Updates height, work, best hash, MMR, and timestamps
    /// 6. **Difficulty Adjustment**: Recalculates difficulty at epoch boundaries
    ///
    /// ## Network-Specific Behavior
    ///
    /// - **Regtest**: Uses minimum difficulty, no difficulty adjustments
    /// - **Testnet4**: Allows emergency difficulty reduction after 20+ minute gaps
    /// - **Others**: Standard Bitcoin difficulty adjustment rules
    ///
    /// ## Parameters
    ///
    /// * `block_headers` - Vector of block headers to process in sequence
    ///
    /// ## Panics
    ///
    /// Panics on any validation failure including invalid hashes, chain breaks,
    /// or timestamp violations.
    pub fn apply_block_headers(&mut self, block_headers: Vec<CircuitBlockHeader>) {
        let mut current_target_bytes = if IS_REGTEST {
            NETWORK_CONSTANTS.max_target.to_be_bytes()
        } else {
            bits_to_target(self.current_target_bits)
        };
        let mut current_work: U256 = U256::from_be_bytes(self.total_work);

        let mut last_block_time = if IS_TESTNET4 {
            if self.block_height == u32::MAX {
                0
            } else {
                self.prev_11_timestamps[self.block_height as usize % 11]
            }
        } else {
            0
        };

        for block_header in block_headers {
            self.block_height = self.block_height.wrapping_add(1);

            let (target_to_use, expected_bits, work_to_add) = if IS_TESTNET4 {
                if block_header.time > last_block_time + 1200 {
                    // If the block is an epoch block, then it still has to have the real target.
                    if self.block_height % BLOCKS_PER_EPOCH == 0 {
                        (
                            current_target_bytes,
                            self.current_target_bits,
                            calculate_work(&current_target_bytes),
                        )
                    }
                    // Otherwise, if the timestamp is more than 20 minutes ahead of the last block, the block is allowed to use the maximum target.
                    else {
                        (
                            NETWORK_CONSTANTS.max_target_bytes,
                            NETWORK_CONSTANTS.max_bits,
                            MINIMUM_WORK_TESTNET,
                        )
                    }
                } else {
                    (
                        current_target_bytes,
                        self.current_target_bits,
                        calculate_work(&current_target_bytes),
                    )
                }
            } else {
                (
                    current_target_bytes,
                    self.current_target_bits,
                    calculate_work(&current_target_bytes),
                )
            };

            let new_block_hash = block_header.compute_block_hash();

            assert_eq!(
                block_header.prev_block_hash, self.best_block_hash,
                "Previous block hash does not match the best block hash. Expected: {:?}, got: {:?}",
                self.best_block_hash, block_header.prev_block_hash
            );

            if IS_REGTEST {
                assert_eq!(
                    block_header.bits, NETWORK_CONSTANTS.max_bits,
                    "Bits for regtest must be equal to the maximum bits: {}. Got: {}",
                    NETWORK_CONSTANTS.max_bits, block_header.bits
                );
            } else {
                assert_eq!(
                    block_header.bits, expected_bits,
                    "Bits for the block header must match the expected bits: {}. Got: {}",
                    expected_bits, block_header.bits
                );
            }

            check_hash_valid(&new_block_hash, &target_to_use);

            if !validate_timestamp(block_header.time, self.prev_11_timestamps) {
                panic!("Timestamp is not valid, it must be greater than the median of the last 11 timestamps");
            }

            self.block_hashes_mmr.append(new_block_hash);
            self.best_block_hash = new_block_hash;
            current_work = current_work.wrapping_add(&work_to_add);

            if !IS_REGTEST && self.block_height % BLOCKS_PER_EPOCH == 0 {
                self.epoch_start_time = block_header.time;
            }

            self.prev_11_timestamps[self.block_height as usize % 11] = block_header.time;

            if IS_TESTNET4 {
                last_block_time = block_header.time;
            }

            if !IS_REGTEST && self.block_height % BLOCKS_PER_EPOCH == BLOCKS_PER_EPOCH - 1 {
                current_target_bytes = calculate_new_difficulty(
                    self.epoch_start_time,
                    block_header.time,
                    self.current_target_bits,
                );
                self.current_target_bits = target_to_bits(&current_target_bytes);
            }
        }

        self.total_work = current_work.to_be_bytes();
    }
}

/// Calculates the median of 11 timestamps.
///
/// Used for Bitcoin's median time past (MTP) rule, which requires that a block's
/// timestamp must be greater than the median of the previous 11 blocks' timestamps.
/// This prevents miners from lying about timestamps to manipulate difficulty.
///
/// ## Parameters
///
/// * `arr` - Array of exactly 11 timestamps as u32 values
///
/// ## Returns
///
/// * `u32` - The median timestamp (6th element when sorted)
fn median(arr: [u32; 11]) -> u32 {
    let mut sorted_arr = arr;
    sorted_arr.sort_unstable();
    sorted_arr[5]
}

/// Validates a block timestamp against the median time past rule.
///
/// Implements Bitcoin's median time past (MTP) validation which requires that
/// each block's timestamp must be strictly greater than the median of the
/// previous 11 blocks' timestamps. This prevents timestamp manipulation attacks.
///
/// ## Parameters
///
/// * `block_time` - The timestamp of the block being validated
/// * `prev_11_timestamps` - Array of the previous 11 block timestamps
///
/// ## Returns
///
/// * `bool` - `true` if the timestamp is valid (greater than median), `false` otherwise
fn validate_timestamp(block_time: u32, prev_11_timestamps: [u32; 11]) -> bool {
    let median_time = median(prev_11_timestamps);
    block_time > median_time
}

/// Converts compact target representation (bits) to full 32-byte target.
///
/// Bitcoin uses a compact representation for difficulty targets in block headers.
/// This function expands the 4-byte compact format into the full 32-byte target
/// that hash values are compared against.
///
/// ## Compact Target Format
///
/// The compact target uses a floating-point-like representation:
/// - Bits 24-31: Size/exponent (how many bytes the mantissa occupies)
/// - Bits 0-23: Mantissa (the significant digits)
///
/// ## Parameters
///
/// * `bits` - Compact target representation from block header
///
/// ## Returns
///
/// * `[u8; 32]` - Full 32-byte target in big-endian format
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let size = (bits >> 24) as usize;
    let mantissa = bits & 0x00ffffff;

    // Mantissa is signed in Bitcoin core, if the sign bit is set, the target is set to 0.
    // https://github.com/bitcoin/bitcoin/blob/ee42d59d4de970769ebabf77b89ff4269498f61e/src/arith_uint256.cpp#L175
    // https://github.com/rust-bitcoin/rust-bitcoin/blob/eb17995e49b68831114cbc8bda14cbe72811c4b7/bitcoin/src/pow.rs#L171
    if mantissa > 0x7F_FFFF {
        return [0; 32];
    }

    let target = if size <= 3 {
        U256::from(mantissa >> (8 * (3 - size)))
    } else {
        U256::from(mantissa) << (8 * (size - 3))
    };
    target.to_be_bytes()
}

/// Converts a full 32-byte target to compact representation (bits).
///
/// This is the inverse of `bits_to_target()`, converting a full 32-byte target
/// back into Bitcoin's compact 4-byte representation used in block headers.
///
/// ## Parameters
///
/// * `target` - Full 32-byte target in big-endian format
///
/// ## Returns
///
/// * `u32` - Compact target representation suitable for block headers
fn target_to_bits(target: &[u8; 32]) -> u32 {
    let target_u256 = U256::from_be_slice(target);
    let target_bits = target_u256.bits();
    let size = (263 - target_bits) / 8;
    let mut compact_target = [0u8; 4];
    compact_target[0] = 33 - size as u8;
    compact_target[1] = target[size - 1_usize];
    compact_target[2] = target[size];
    compact_target[3] = target[size + 1_usize];
    u32::from_be_bytes(compact_target)
}

/// Calculates the new difficulty target after a difficulty adjustment epoch.
///
/// Bitcoin adjusts difficulty every 2016 blocks to maintain ~10 minute block times.
/// The adjustment is based on how long the previous 2016 blocks actually took
/// compared to the expected timespan (2 weeks).
///
/// ## Algorithm
///
/// 1. Calculate actual timespan: `last_timestamp - epoch_start_time`
/// 2. Clamp timespan to [expected/4, expected*4] to limit adjustment range
/// 3. New target = old target * actual_timespan / expected_timespan
/// 4. Ensure new target doesn't exceed network maximum
///
/// ## Parameters
///
/// * `epoch_start_time` - Timestamp of the first block in the epoch
/// * `last_timestamp` - Timestamp of the last block in the epoch  
/// * `current_target` - Current difficulty target in compact format
///
/// ## Returns
///
/// * `[u8; 32]` - New difficulty target as 32-byte array
fn calculate_new_difficulty(
    epoch_start_time: u32,
    last_timestamp: u32,
    current_target: u32,
) -> [u8; 32] {
    let mut actual_timespan = last_timestamp - epoch_start_time;
    if actual_timespan < EXPECTED_EPOCH_TIMESPAN / 4 {
        actual_timespan = EXPECTED_EPOCH_TIMESPAN / 4;
    } else if actual_timespan > EXPECTED_EPOCH_TIMESPAN * 4 {
        actual_timespan = EXPECTED_EPOCH_TIMESPAN * 4;
    }

    let current_target_bytes = bits_to_target(current_target);
    let mut new_target = U256::from_be_bytes(current_target_bytes)
        .wrapping_mul(&U256::from(actual_timespan))
        .wrapping_div(&U256::from(EXPECTED_EPOCH_TIMESPAN));

    if new_target > NETWORK_CONSTANTS.max_target {
        new_target = NETWORK_CONSTANTS.max_target;
    }
    new_target.to_be_bytes()
}

/// Validates that a block hash meets the proof-of-work requirement.
///
/// Compares the block hash against the difficulty target to ensure sufficient
/// work was performed. The hash is interpreted as a big-endian 256-bit integer
/// and must be less than or equal to the target.
///
/// Bitcoin uses little-endian byte order for hashes in most contexts, but for
/// difficulty comparison the hash bytes are reversed to big-endian format.
///
/// ## Parameters
///
/// * `hash` - The block hash to validate (32 bytes, little-endian)
/// * `target_bytes` - The difficulty target (32 bytes, big-endian)
///
/// ## Panics
///
/// Panics with "Hash is not valid" if the hash exceeds the target.
fn check_hash_valid(hash: &[u8; 32], target_bytes: &[u8; 32]) {
    for i in 0..32 {
        match hash[31 - i].cmp(&target_bytes[i]) {
            Ordering::Less => return,
            Ordering::Greater => panic!("Hash is not valid"),
            Ordering::Equal => continue,
        }
    }
}

/// Calculates the amount of work represented by a difficulty target.
///
/// Bitcoin measures cumulative proof-of-work as the sum of work done by all blocks.
/// The work for a single block is inversely proportional to its target:
/// work = 2 ** 256 / (target + 1)
///
/// This calculation uses the mathematical identity:
/// 2**256 / (x + 1) == ~x / (x + 1) + 1
/// (Equation shamelessly stolen from bitcoind)
///
/// This allows comparing the total work between different chains to determine
/// which has the most accumulated proof-of-work.
///
/// ## Parameters
///
/// * `target` - The difficulty target as a 32-byte big-endian array
///
/// ## Returns
///
/// * `U256` - The amount of work represented by this target
fn calculate_work(target: &[u8; 32]) -> U256 {
    // We should never have a target/work of zero so this doesn't matter
    // that much but we define the inverse of 0 as max.
    let target = U256::from_be_slice(target);
    if target == U256::ZERO {
        return U256::MAX;
    }
    // We define the inverse of 1 as max.
    if target == U256::ONE {
        return U256::MAX;
    }
    // We define the inverse of max as 1.
    if target == U256::MAX {
        return U256::ONE;
    }

    let comp = !target;

    let ret = comp.wrapping_div(&target.wrapping_add(&U256::ONE));
    ret.wrapping_add(&U256::ONE)
}

/// Circuit output containing the updated chain state and metadata.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct BlockHeaderCircuitOutput {
    pub method_id: [u32; 8],
    pub genesis_state_hash: [u8; 32],
    pub chain_state: ChainState,
}

/// Previous proof type - either genesis state or previous circuit output.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum HeaderChainPrevProofType {
    GenesisBlock(ChainState),
    PrevProof(BlockHeaderCircuitOutput),
}

/// The input of the header chain circuit.
/// It contains the method ID, the previous proof (either a genesis block or a previous proof), and the block headers to be processed.
/// Method ID is used to identify the circuit and is expected to be the same as the one used in the previous proof.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct HeaderChainCircuitInput {
    pub method_id: [u32; 8],
    pub prev_proof: HeaderChainPrevProofType,
    pub block_headers: Vec<CircuitBlockHeader>,
}

#[cfg(test)]
mod tests {
    use crate::header_chain::tests::data::CHAINWORK_TEST_HASHES;

    use super::*;
    use hex_literal::hex;

    #[path = "data.rs"]
    mod data;
    use data::{BLOCK_HEADERS, DIFFICULTY_ADJUSTMENTS};

    #[test]
    fn test_block_hash_calculation() {
        let merkle_root = hex!("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a");
        let expected_block_hash =
            hex!("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");

        let block_header = CircuitBlockHeader {
            version: 1,
            prev_block_hash: [0u8; 32],
            merkle_root,
            time: 1231006505,
            bits: 486604799,
            nonce: 2083236893,
        };

        let block_hash = block_header.compute_block_hash();
        assert_eq!(block_hash, expected_block_hash);
    }

    #[test]
    fn test_15_block_hash_calculation() {
        let block_headers = BLOCK_HEADERS
            .iter()
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        for i in 0..block_headers.len() - 1 {
            let block_hash = block_headers[i].compute_block_hash();
            let next_block = &block_headers[i + 1];
            assert_eq!(block_hash, next_block.prev_block_hash);
        }
    }

    #[test]
    fn test_median() {
        let arr = [3, 7, 2, 10, 1, 5, 9, 4, 8, 6, 11];
        assert_eq!(median(arr), 6);
    }

    #[test]
    fn test_timestamp_check_fail() {
        let block_headers = BLOCK_HEADERS
            .iter()
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        let first_11_timestamps = block_headers[..11]
            .iter()
            .map(|header| header.time)
            .collect::<Vec<u32>>();

        // The validation is expected to return false
        assert!(!validate_timestamp(
            block_headers[1].time,
            first_11_timestamps.try_into().unwrap(),
        ));
    }

    #[test]
    fn test_timestamp_check_pass() {
        let block_headers = BLOCK_HEADERS
            .iter()
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        let first_11_timestamps = block_headers[..11]
            .iter()
            .map(|header| header.time)
            .collect::<Vec<u32>>();

        assert!(validate_timestamp(
            block_headers[11].time,
            first_11_timestamps.clone().try_into().unwrap(),
        ));
    }

    #[test]
    #[should_panic(expected = "Hash is not valid")]
    fn test_hash_check_fail() {
        let block_headers = BLOCK_HEADERS
            .iter()
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        let first_15_hashes = block_headers[..15]
            .iter()
            .map(|header| header.compute_block_hash())
            .collect::<Vec<[u8; 32]>>();

        // The validation is expected to panic
        check_hash_valid(
            &first_15_hashes[0],
            &U256::from_be_hex("00000000FFFF0000000000000000000000000000000000000000000000000000")
                .wrapping_div(&(U256::ONE << 157))
                .to_be_bytes(),
        );
    }

    #[test]
    fn test_hash_check_pass() {
        let block_headers = BLOCK_HEADERS
            .iter()
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        let first_15_hashes = block_headers[..15]
            .iter()
            .map(|header| header.compute_block_hash())
            .collect::<Vec<[u8; 32]>>();

        for (i, hash) in first_15_hashes.into_iter().enumerate() {
            check_hash_valid(&hash, &bits_to_target(block_headers[i].bits));
        }
    }

    #[test]
    fn test_target_conversion() {
        for (_, _, bits, _) in DIFFICULTY_ADJUSTMENTS {
            let compact_target = bits_to_target(bits);
            let nbits = target_to_bits(&compact_target);
            assert_eq!(nbits, bits);
        }
    }

    #[test]
    fn test_bits_to_target() {
        // https://learnmeabitcoin.com/explorer/block/00000000000000000002ebe388cb8fa0683fc34984cfc2d7d3b3f99bc0d51bfd
        let expected_target =
            hex!("00000000000000000002f1280000000000000000000000000000000000000000");
        let bits: u32 = 0x1702f128;
        let target = bits_to_target(bits);
        assert_eq!(target, expected_target);

        let converted_bits = target_to_bits(&target);

        assert_eq!(converted_bits, bits);
    }

    #[test]
    fn test_difficulty_adjustments() {
        for (start_time, end_time, start_target, end_target) in DIFFICULTY_ADJUSTMENTS {
            let new_target_bytes = calculate_new_difficulty(start_time, end_time, start_target);
            let bits = target_to_bits(&new_target_bytes);
            assert_eq!(bits, end_target);
        }
    }

    #[test]
    fn test_bridge_block_header_from_header() {
        let header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_slice(&[0; 32]).unwrap(),
            merkle_root: TxMerkleNode::from_slice(&[1; 32]).unwrap(),
            time: 1231006505,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2083236893,
        };

        let bridge_header: CircuitBlockHeader = header.into();

        assert_eq!(bridge_header.version, header.version.to_consensus());
        assert_eq!(
            bridge_header.prev_block_hash,
            *header.prev_blockhash.as_byte_array()
        );
        assert_eq!(
            bridge_header.merkle_root,
            *header.merkle_root.as_byte_array()
        );
        assert_eq!(bridge_header.time, header.time);
        assert_eq!(bridge_header.bits, header.bits.to_consensus());
        assert_eq!(bridge_header.nonce, header.nonce);
        assert_eq!(
            bridge_header.compute_block_hash(),
            header.block_hash().to_byte_array()
        );
    }

    #[test]
    fn test_bridge_block_header_into_header() {
        let bridge_header = CircuitBlockHeader {
            version: 1,
            prev_block_hash: [0; 32],
            merkle_root: [1; 32],
            time: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };

        let header: Header = bridge_header.clone().into();

        assert_eq!(header.version.to_consensus(), bridge_header.version);
        assert_eq!(
            *header.prev_blockhash.as_byte_array(),
            bridge_header.prev_block_hash
        );
        assert_eq!(
            *header.merkle_root.as_byte_array(),
            bridge_header.merkle_root
        );
        assert_eq!(header.time, bridge_header.time);
        assert_eq!(header.bits.to_consensus(), bridge_header.bits);
        assert_eq!(header.nonce, bridge_header.nonce);
        assert_eq!(
            header.block_hash().to_byte_array(),
            bridge_header.compute_block_hash()
        );
    }

    #[test]
    fn test_roundtrip_header_conversion() {
        let original_header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_slice(&[0; 32]).unwrap(),
            merkle_root: TxMerkleNode::from_slice(&[1; 32]).unwrap(),
            time: 1231006505,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2083236893,
        };

        let bridge_header: CircuitBlockHeader = original_header.into();
        let converted_header: Header = bridge_header.into();

        assert_eq!(original_header, converted_header);
        assert_eq!(original_header.block_hash(), converted_header.block_hash());
    }

    #[test]
    fn test_calculate_work() {
        let mut target: [u8; 32] = [0u8; 32];
        let work = calculate_work(&target);
        assert_eq!(work, U256::MAX);
        target[31] = 1;
        let work = calculate_work(&target);
        assert_eq!(work, U256::MAX);
        let target: [u8; 32] = [0xFF; 32];
        let work = calculate_work(&target);
        assert_eq!(work, U256::ONE);

        let target: [u8; 32] =
            hex!("00000000FFFF0000000000000000000000000000000000000000000000000000");
        let work = calculate_work(&target);
        assert_eq!(work, MINIMUM_WORK_TESTNET);
    }

    #[test]
    fn test_mainnet_chainworks() {
        for (bits, expected_chainwork, prev_chainwork) in CHAINWORK_TEST_HASHES {
            let bits: u32 = u32::from_str_radix(bits, 16).unwrap();
            let expected_chainwork = U256::from_be_hex(expected_chainwork);
            let prev_chainwork = U256::from_be_hex(prev_chainwork);
            let target = bits_to_target(bits);
            let calculated_chainwork = calculate_work(&target);
            assert_eq!(
                calculated_chainwork.wrapping_add(&prev_chainwork),
                expected_chainwork
            );
        }
    }
}
