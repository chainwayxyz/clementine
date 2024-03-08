use crypto_bigint::Encoding;
use crypto_bigint::U256;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ScalarPrimitive;
use k256::{AffinePoint, PublicKey, Scalar};

use crate::double_sha256_hash;
use crate::env::Environment;
use crate::sha256_hash;
use crate::HashType;
use sha2::{Digest, Sha256};

// /// Data is generic type we use to represent 32 bytes of data
// pub type Data = [u8; 32];
pub type HeaderWithoutPrevBlockHash = (i32, HashType, u32, u32, u32);

pub fn validate_threshold_and_add_work(
    bits: [u8; 4],
    block_hash: [u8; 32],
    old_work: U256,
) -> U256 {
    // Step 1: Decode the target from the 'bits' field
    let target = decode_compact_target(bits);

    // Step 2: Compare the block hash with the target
    check_hash_valid(block_hash, target);

    // Step 3: Calculate work
    let work = calculate_work(target);

    old_work.wrapping_add(&work)
}

pub fn validate_threshold_and_subtract_work(
    bits: [u8; 4],
    block_hash: [u8; 32],
    old_work: U256,
) -> U256 {
    // Step 1: Decode the target from the 'bits' field
    let target = decode_compact_target(bits);

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
    for i in (0..32).rev() {
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

    U256::MAX.wrapping_div(&target_plus_one)
}

pub fn get_script_hash(
    actor_pk_bytes: [u8; 32],
    preimages: &[u8],
    number_of_preimages: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let tap_leaf_str = "TapLeaf";
    let tap_leaf_tag_hash: [u8; 32] = sha256_hash!(&tap_leaf_str.as_bytes());
    hasher.update(tap_leaf_tag_hash);
    hasher.update(tap_leaf_tag_hash);
    hasher.update([192u8]);
    let script_length: u8 = 37 + 33 * number_of_preimages;
    hasher.update([script_length]);
    hasher.update([32u8]);
    hasher.update(actor_pk_bytes);
    hasher.update([172u8, 0u8, 99u8]);
    for i in 0..number_of_preimages as usize {
        let preimage = &preimages[i * 32..(i + 1) * 32];
        hasher.update([32u8]);
        hasher.update(preimage);
    }
    hasher.update([104u8]);
    hasher.finalize().into()
}

pub fn read_preimages_and_calculate_commit_taproot<E: Environment>() -> ([u8; 32], [u8; 32]) {
    let num_preimages = E::read_u32();
    let actor_pk_bytes = E::read_32bytes();
    let mut hasher_commit_taproot = Sha256::new();
    let mut hasher_claim_proof_leaf = Sha256::new();
    let tap_leaf_str = "TapLeaf";
    let tap_leaf_tag_hash: [u8; 32] = sha256_hash!(&tap_leaf_str.as_bytes());
    hasher_commit_taproot.update(tap_leaf_tag_hash);
    hasher_commit_taproot.update(tap_leaf_tag_hash);
    hasher_commit_taproot.update([192u8]);
    let script_length = 37 + 33 * num_preimages;
    update_hasher_with_varint(&mut hasher_commit_taproot, script_length);
    hasher_commit_taproot.update([32u8]);
    hasher_commit_taproot.update(actor_pk_bytes);
    hasher_commit_taproot.update([172u8, 0u8, 99u8]);
    for _ in 0..num_preimages {
        hasher_commit_taproot.update([32u8]);
        let preimage = E::read_32bytes();
        hasher_commit_taproot.update(&preimage);
        hasher_claim_proof_leaf.update(&preimage);
    }
    hasher_commit_taproot.update([104u8]);
    let script_hash: [u8; 32] = hasher_commit_taproot.finalize().into();
    let claim_proof_leaf: [u8; 32] = hasher_claim_proof_leaf.finalize().into();
    let taproot_address = calculate_taproot_from_single_script(script_hash);

    return (taproot_address, claim_proof_leaf);
}

pub fn calculate_taproot_from_single_script(tap_leaf_hash: [u8; 32]) -> [u8; 32] {
    // internal key as bytes
    let internal_key_x_only_bytes: [u8; 32] = [
        147, 199, 55, 141, 150, 81, 138, 117, 68, 136, 33, 196, 247, 200, 244, 186, 231, 206, 96,
        248, 4, 208, 61, 31, 6, 40, 221, 93, 208, 245, 222, 81,
    ];
    let internal_key_y_only_bytes: [u8; 32] = [
        183, 230, 72, 141, 245, 65, 139, 76, 55, 246, 18, 113, 172, 165, 3, 144, 103, 1, 56, 183,
        220, 79, 77, 28, 43, 146, 127, 196, 59, 144, 15, 40,
    ];
    let mut internal_key_bytes = [0u8; 65];
    internal_key_bytes[0] = 4;
    internal_key_bytes[1..33].copy_from_slice(&internal_key_x_only_bytes);
    internal_key_bytes[33..65].copy_from_slice(&internal_key_y_only_bytes);
    //internal key as public key
    let internal_key = PublicKey::from_sec1_bytes(&internal_key_bytes).unwrap();
    // tap_leaf_hash is the merkle tree root
    let tap_tweak_str = "TapTweak";
    let tap_tweak_tag_hash = sha256_hash!(&tap_tweak_str.as_bytes());
    let tweak_hash = sha256_hash!(
        &tap_tweak_tag_hash,
        &tap_tweak_tag_hash,
        &internal_key_x_only_bytes,
        &tap_leaf_hash
    );
    // internal_key.tap_tweak(secp, merkle_root);
    let scalar_primitive = ScalarPrimitive::from_slice(&tweak_hash).unwrap();
    let scalar = Scalar::from(scalar_primitive);
    let scalar_point = AffinePoint::GENERATOR * scalar;
    let tweaked_output = internal_key.to_projective() + scalar_point;
    let address = tweaked_output.to_affine();
    let mut address_bytes = [0u8; 33];
    address_bytes[0..33].copy_from_slice(&address.to_bytes()[0..33]);
    address_bytes[1..33].try_into().unwrap()
}

// pub fn read_tx_and_calculate_txid<E: Environment>() -> [u8; 32] {
//     let version = E::read_i32();
//     let input_count: u8 = E::read_u32().try_into().unwrap();
//     let output_count: u8 = E::read_u32().try_into().unwrap();
//     let lock_time = E::read_u32();

//     let mut hasher = Sha256::new();
//     hasher.update(&version.to_le_bytes());
//     hasher.update(&input_count.to_le_bytes());
//     for _ in 0..input_count {
//         let prev_tx_hash = E::read_32bytes();
//         let output_index = E::read_u32();
//         let sequence = E::read_u32();
//         hasher.update(&prev_tx_hash);
//         hasher.update(&output_index.to_le_bytes());
//         hasher.update(&0u8.to_le_bytes());
//         hasher.update(&sequence.to_le_bytes());
//     }
//     hasher.update(&output_count.to_le_bytes());
//     for _ in 0..output_count {
//         let value = E::read_u64();
//         let taproot_address = E::read_32bytes();
//         hasher.update(&value.to_le_bytes());
//         hasher.update(&34u8.to_le_bytes());
//         hasher.update(&81u8.to_le_bytes());
//         hasher.update(&32u8.to_le_bytes());
//         hasher.update(&taproot_address);
//     }
//     hasher.update(&lock_time.to_le_bytes());
//     let result = hasher.finalize_reset();
//     hasher.update(result);
//     hasher.finalize().try_into().unwrap()
// }

// updates the hasher with variable length integer
fn update_hasher_with_varint(hasher: &mut Sha256, integer: u32) {
    if integer < 0xfd {
        hasher.update((integer as u8).to_le_bytes());
    } else if integer <= 0xffff {
        hasher.update(0xfdu8.to_le_bytes());
        hasher.update((integer as u16).to_le_bytes());
    } else {
        hasher.update(0xfeu8.to_le_bytes());
        hasher.update(integer.to_le_bytes());
    }
}

fn read_chunks_and_update_hasher<E: Environment>(hasher: &mut Sha256, byte_len: u32) {
    let chunks = byte_len / 32;
    for _ in 0..chunks {
        let chunk = E::read_32bytes();
        hasher.update(chunk);
    }
    let remaining_bytes = byte_len % 32;
    if remaining_bytes > 0 {
        let chunk = E::read_32bytes();
        hasher.update(&chunk[..remaining_bytes as usize]);
    }
}

pub fn read_tx_and_calculate_txid<E: Environment>(
    require_input: Option<([u8; 32], u32)>,
    require_output: Option<(u64, [u8; 32])>,
) -> [u8; 32] {
    let mut input_satisfied = require_input.is_none();
    let mut output_satisfied = require_output.is_none();
    let version = E::read_i32();
    let input_count = E::read_u32();
    let output_count = E::read_u32();
    let lock_time = E::read_u32();

    let mut hasher = Sha256::new();
    hasher.update(version.to_le_bytes());

    update_hasher_with_varint(&mut hasher, input_count);

    for _ in 0..input_count {
        let prev_tx_hash = E::read_32bytes();
        let output_index = E::read_u32();
        let sequence = E::read_u32();
        hasher.update(prev_tx_hash);
        hasher.update(output_index.to_le_bytes());

        let script_sig_size = E::read_u32();

        update_hasher_with_varint(&mut hasher, script_sig_size);

        read_chunks_and_update_hasher::<E>(&mut hasher, script_sig_size);

        // hasher.update(0u8.to_le_bytes());
        hasher.update(sequence.to_le_bytes());
        if require_input.is_some()
            && !input_satisfied
            && prev_tx_hash == require_input.unwrap().0
            && output_index == require_input.unwrap().1
        {
            input_satisfied = true;
        }
    }

    update_hasher_with_varint(&mut hasher, output_count);

    for _ in 0..output_count {
        let value = E::read_u64();
        let output_len = E::read_u32();
        // if output_type == 0, this means it is a taproot output
        // else output_len is number of 32 byte chunks, for the last chunk,
        // it can be less than 32 bytes so we read the remaining bytes
        if output_len == 0 {
            let taproot_address = E::read_32bytes();
            hasher.update(value.to_le_bytes());
            hasher.update(34u8.to_le_bytes());
            hasher.update(81u8.to_le_bytes());
            hasher.update(32u8.to_le_bytes());
            hasher.update(taproot_address);
            if require_output.is_some()
                && !output_satisfied
                && value == require_output.unwrap().0
                && taproot_address == require_output.unwrap().1
            {
                output_satisfied = true;
            }
        } else {
            hasher.update(value.to_le_bytes());

            update_hasher_with_varint(&mut hasher, output_len);

            read_chunks_and_update_hasher::<E>(&mut hasher, output_len);
        }
    }
    if !input_satisfied {
        panic!("Input not found");
    }
    if !output_satisfied {
        panic!("Output not found");
    }
    // if !output_address_found {
    //     panic!("Output address not found");
    // }
    hasher.update(lock_time.to_le_bytes());
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

pub fn read_and_verify_bitcoin_merkle_path<E: Environment>(txid: [u8; 32]) -> [u8; 32] {
    let mut hash = txid;
    let mut index = E::read_u32();
    let levels = E::read_u32();
    // bits of path indicator determines if the next tree node should be read from env or be the copy of last node
    let mut path_indicator = E::read_u32();
    for _ in 0..levels {
        let node = if path_indicator & 1 == 1 {
            hash
        } else {
            E::read_32bytes()
        };
        path_indicator >>= 1;
        hash = if index & 1 == 0 {
            double_sha256_hash!(&hash, &node)
        } else {
            double_sha256_hash!(&node, &hash)
        };
        index /= 2;
    }
    hash
}
