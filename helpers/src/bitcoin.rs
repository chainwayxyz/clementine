use crypto_bigint::Encoding;
use crypto_bigint::U256;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ScalarPrimitive;
use k256::{AffinePoint, PublicKey, Scalar};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

pub fn validate_threshold_and_subtract_work(
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

    old_work.wrapping_sub(&work)
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

pub fn get_script_hash(actor_pk_bytes: [u8; 32], preimages: &[u8], number_of_preimages: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let tap_leaf_str = "TapLeaf";
    let tap_leaf_tag_hash: [u8; 32] = calculate_single_sha256(&tap_leaf_str.as_bytes());
    let mut hash_tag = [0u8; 64];
    hash_tag[..32].copy_from_slice(&tap_leaf_tag_hash);
    hash_tag[32..64].copy_from_slice(&tap_leaf_tag_hash);
    hasher.update(&hash_tag);
    hasher.update(&[192u8]);
    let script_length: u8 = 37 + 33 * number_of_preimages;
    hasher.update(&[script_length]);
    hasher.update(&[32u8]);
    hasher.update(&actor_pk_bytes);
    hasher.update(&[172u8, 0u8, 99u8]);
    for i in 0..number_of_preimages as usize {
        let preimage = &preimages[i * 32..(i+1) * 32];
        hasher.update(&[32u8]);
        hasher.update(preimage);
    }
    hasher.update(&[104u8]);
    hasher.finalize().try_into().unwrap()
}

pub fn verify_script_hash_taproot_address(actor_pk_bytes: [u8; 32], preimages: &[u8], number_of_preimages: u8, tap_leaf_hash: [u8; 32], taproot_address: [u8; 32]) -> (bool, [u8; 33], &[u8]) {
    assert!(get_script_hash(actor_pk_bytes, preimages, number_of_preimages) == tap_leaf_hash, "Script hash does not match tap leaf hash");
    // internal key as bytes
    let internal_key_x_only_bytes: [u8; 32] = from_hex64_to_bytes32("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51");
    let internal_key_y_only_bytes: [u8; 32] = from_hex64_to_bytes32("b7e6488df5418b4c37f61271aca50390670138b7dc4f4d1c2b927fc43b900f28");
    let mut internal_key_bytes = [0u8; 65];
    internal_key_bytes[0] = 4;
    internal_key_bytes[1..33].copy_from_slice(&internal_key_x_only_bytes);
    internal_key_bytes[33..65].copy_from_slice(&internal_key_y_only_bytes);
    //internal key as public key
    let internal_key = PublicKey::from_sec1_bytes(&internal_key_bytes).unwrap();
    // tap_leaf_hash is the merkle tree root
    let tap_tweak_str = "TapTweak";
    let tap_tweak_tag_hash = calculate_single_sha256(&tap_tweak_str.as_bytes());
    let mut tweak_hash_input: [u8; 128] = [0u8; 128];
    tweak_hash_input[..32].copy_from_slice(&tap_tweak_tag_hash);
    tweak_hash_input[32..64].copy_from_slice(&tap_tweak_tag_hash);
    tweak_hash_input[64..96].copy_from_slice(&internal_key_x_only_bytes);
    tweak_hash_input[96..128].copy_from_slice(&tap_leaf_hash);
    // tweak_hash is the tweak scalar
    let tweak_hash = calculate_single_sha256(&tweak_hash_input);
    let scalar_primitive = ScalarPrimitive::from_slice(&tweak_hash).unwrap();
    let scalar = Scalar::from(scalar_primitive);
    let scalar_point = AffinePoint::GENERATOR * scalar;
    let tweaked_output = internal_key.to_projective() + scalar_point;
    let address = tweaked_output.to_affine();
    let mut address_bytes = [0u8; 33];
    address_bytes[0..33].copy_from_slice(&address.to_bytes()[0..33]);
    // internal_key.tap_tweak(secp, merkle_root);
    return (address_bytes[1..33] == taproot_address, address_bytes, preimages);
}
