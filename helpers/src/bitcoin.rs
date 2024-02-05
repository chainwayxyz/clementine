use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::scalar::Scalar;
use bitcoin::taproot::TAPROOT_LEAF_TAPSCRIPT;
use crypto_bigint::Encoding;
use crypto_bigint::U256;

use serde::{Deserialize, Serialize};

use crate::config::CONNECTOR_TREE_DEPTH;
use crate::core_utils::from_hex64_to_bytes32;
use crate::hashes::calculate_single_sha256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockHeader {
    pub version: [u8; 4],
    pub previous_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: [u8; 4],
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
}

impl BlockHeader {
    pub fn from_slice(input: &[u8; 80]) -> Self {
        BlockHeader {
            version: input[0..4].try_into().unwrap(),
            previous_block_hash: input[4..36].try_into().unwrap(),
            merkle_root: input[36..68].try_into().unwrap(),
            timestamp: input[68..72].try_into().unwrap(),
            bits: input[72..76].try_into().unwrap(),
            nonce: input[76..80].try_into().unwrap(),
        }
    }

    pub fn as_bytes(&self) -> [u8; 80] {
        let mut output: [u8; 80] = [0; 80];
        output[0..4].copy_from_slice(&self.version);
        output[4..36].copy_from_slice(&self.previous_block_hash);
        output[36..68].copy_from_slice(&self.merkle_root);
        output[68..72].copy_from_slice(&self.timestamp);
        output[72..76].copy_from_slice(&self.bits);
        output[76..80].copy_from_slice(&self.nonce);
        output
    }
}

pub fn validate_threshold_and_add_work(
    block_header: BlockHeader,
    block_hash: [u8; 32],
    old_work: U256,
) -> U256 {
    // Step 1: Decode the target from the 'bits' field
    let target = decode_compact_target(block_header.bits);

    // Step 2: Compare the block hash with the target
    check_hash_valid(block_hash, target);

    // Step 3: Calculate work
    let work = calculate_work(target);

    old_work.wrapping_add(&work)
}

pub fn decode_compact_target(bits: [u8; 4]) -> [u8; 32] {
    let mut bits = bits;
    bits.reverse();

    let mut target = [0u8; 32];
    let exponent = bits[0] as usize;
    let value = ((bits[1] as u32) << 16) | ((bits[2] as u32) << 8) | (bits[3] as u32);

    if exponent <= 3 {
        // If the target size is 3 bytes or less, place the value at the end
        let start_index = 4 - exponent;
        for i in 0..exponent {
            target[31 - i] = (value >> (8 * (start_index + i))) as u8;
        }
    } else {
        // If the target size is more than 3 bytes, place the value at the beginning and shift accordingly
        for i in 0..3 {
            target[exponent - 3 + i] = (value >> (8 * i)) as u8;
        }
    }

    target
}

fn check_hash_valid(hash: [u8; 32], target: [u8; 32]) {
    // for loop from 31 to 0
    for i in  (0..32).rev() {
        if hash[i] < target[i] {
            // The hash is valid because a byte in hash is less than the corresponding byte in target
            return;
        } else if hash[i] > target[i] {
            // The hash is invalid because a byte in hash is greater than the corresponding byte in target
            panic!("Hash is not valid");
        }
        // If the bytes are equal, continue to the next byte
    }
    // If we reach this point, all bytes are equal, so the hash is valid
}

pub fn calculate_work(target: [u8; 32]) -> U256 {
    let target_plus_one = U256::from_le_bytes(target).saturating_add(&U256::ONE);
    let work = U256::MAX.wrapping_div(&target_plus_one);
    work
}


//change preimages length later
pub fn verify_preimage_reveal_taproot_address(secp: &Secp256k1<All>, actor_pk: XOnlyPublicKey, preimages: [[u8; 32]; 2], taproot_address: [u8; 32]) -> bool {
    let actor_pk_bytes = actor_pk.serialize();
    let internal_key_bytes: [u8; 32] = from_hex64_to_bytes32("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51");
    let internal_key = XOnlyPublicKey::from_slice(&internal_key_bytes).unwrap();
    let mut script = [0u8; 37 + 33 * 2];
    script[0] = 32;
    script[1..33].copy_from_slice(&actor_pk_bytes);
    script[33] = 172;
    script[34] = 0;
    script[35] = 99;
    for i in 0..2 {
        script[36 + 33 * i] = 32;
        script[37 + 33 * i..36 + 33 * (i + 1)].copy_from_slice(&preimages[i]);
    }
    script[102] = 104;
    // let mut script_rev = script.clone();
    // script_rev.reverse();
    let tap_leaf_str = "TapLeaf";
    // let mut tap_leaf_bytes = [0u8; 7];
    // tap_leaf_bytes.copy_from_slice(tap_leaf_str.as_bytes());
    // tap_leaf_bytes.reverse();
    let tap_leaf_tag_hash = calculate_single_sha256(&tap_leaf_str.as_bytes());
    // tap_leaf_tag_hash.reverse();
    const LEN_TAP_LEAF_HASH_INPUT: usize = 102 + 33 * 2 + 1;
    let mut tap_leaf_hash_input = [0u8; LEN_TAP_LEAF_HASH_INPUT];
    tap_leaf_hash_input[..32].copy_from_slice(&tap_leaf_tag_hash);
    tap_leaf_hash_input[32..64].copy_from_slice(&tap_leaf_tag_hash);
    tap_leaf_hash_input[64] = TAPROOT_LEAF_TAPSCRIPT;
    tap_leaf_hash_input[65] = 103;
    tap_leaf_hash_input[66..LEN_TAP_LEAF_HASH_INPUT].copy_from_slice(&script);
    // tap_leaf_hash is the merkle tree root
    let tap_leaf_hash = calculate_single_sha256(&tap_leaf_hash_input);
    // let tap_node_str = "TapBranch";
    // let tap_node_tag_hash = calculate_single_sha256(&tap_node_str.as_bytes());
    // tap_node_tag_hash.reverse();
    // let mut tap_node_hash_input: [u8; 96] = [0u8; 96];
    // tap_node_hash_input[..32].copy_from_slice(&tap_node_tag_hash);
    // tap_node_hash_input[32..64].copy_from_slice(&tap_node_tag_hash);
    // tap_node_hash_input[64..96].copy_from_slice(&tap_leaf_hash);
    // tap_node_hash_input.reverse();
    // let tap_node_hash = calculate_single_sha256(&tap_node_hash_input);
    let tap_tweak_str = "TapTweak";
    let tap_tweak_tag_hash = calculate_single_sha256(&tap_tweak_str.as_bytes());
    // tap_tweak_tag_hash.reverse();
    // let tag_pubkey_hash = calculate_double_sha256(&tap_tweak_bytes);
    let mut tweak_hash_input: [u8; 128] = [0u8; 128];
    tweak_hash_input[..32].copy_from_slice(&tap_tweak_tag_hash);
    tweak_hash_input[32..64].copy_from_slice(&tap_tweak_tag_hash);
    tweak_hash_input[64..96].copy_from_slice(&internal_key_bytes);
    tweak_hash_input[96..128].copy_from_slice(&tap_leaf_hash);
    // let mut tweak: [u8; 128] = [0u8; 128];
    // tweak[..32].copy_from_slice(&tag_pubkey_hash);
    // tweak[32..64].copy_from_slice(&tag_pubkey_hash);
    // tweak[64..128].copy_from_slice(&tweak_input);
    // tweak_hash is the tweak scalar
    let tweak_hash = calculate_single_sha256(&tweak_hash_input);
    let scalar = Scalar::from_be_bytes(tweak_hash).unwrap();
    let (output, _parity) = internal_key.add_tweak(secp, &scalar).unwrap();
    let address = output.serialize();
    // internal_key.tap_tweak(secp, merkle_root);
    return address == taproot_address;
}
