//! # Bridge Circuit Constants
//!
//! This module contains constants used in the bridge circuit, including method IDs for different networks,
//! Groth16 related constants, and prepared verification keys. These constants are essential for the operation
//! of the bridge circuit and are used in various cryptographic operations.
//! ## Work-Only Circuit Method IDs
//! The method IDs for different networks are used to identify the specific work-only circuits.
//! They are used for verifying the total work done on a Bitcoin blockchain for a given Watchtower challenge.
//! ## Groth16 Related Constants
//! These constants are used in the Groth16 proof verification process.
//! They include the post state, input, assumptions, claim tag, and output tag.
//! They are used to recover all five public outputs of the Groth16 proof when Risc0 pipeline is used
//! for generating the proof.
//! ## Verification Keys
//! The prepared verification keys are used to verify the Groth16 proofs. They are included in
//! the binary format. The `get_prepared_vk` function can be used to retrieve the appropriate
//! verification key according to the feature flags.

use ark_bn254::Fr;
use ark_ff::BigInt;
use hex_literal::hex;

pub const REGTEST_LC_IMAGE_ID: [u8; 32] =
    hex!("e02f42a01d0cb5a6dbc2f5d26b28a9881808a3023c8330a5aea2a0bea754c216");

pub const DEVNET_LC_IMAGE_ID: [u8; 32] =
    hex!("3d8dc93f82c5aca7ed513f30eebf6fc1580fc3ad3e7b1e65912fc2ace1a9a3f6");

pub const TESTNET_LC_IMAGE_ID: [u8; 32] =
    hex!("19b3bc65347ca0499f2a8f71117fe924df4b9c1c2a93eb4dd70df939490256fe");

// MAINNET LC_IMAGE_ID is not yet provided by CITREA, so we use a placeholder.
pub const MAINNET_LC_IMAGE_ID: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000000");

// Work-only circuit method IDs for different networks.
pub static MAINNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("ba2bd4e46597ab3341f0ed4fde263f35b82da3ec3fe6f42d85399b8c61a4fba2");
pub static TESTNET4_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("f32a967a3557f87e3d67821ae8cfa845429edc224c0f1df86996dd41914b2596");
pub static REGTEST_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("11bb884b51d9d33de10ea449927b932ada1c540acd9dfc03e9af806dc8180979");
pub static SIGNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("35d88de6b8a13cfe34df05e103d14f926d1a56671792c2ce85b89f055193f225");

// GROTH16 RELATED CONSTANTS
pub static POST_STATE: [u8; 32] =
    hex_literal::hex!("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2");
pub static INPUT: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static ASSUMPTIONS: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static CLAIM_TAG: [u8; 32] =
    hex_literal::hex!("cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"); // SHA256 hash of "risc0.ReceiptClaim"
pub static OUTPUT_TAG: [u8; 32] =
    hex_literal::hex!("77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"); // SHA256 hash of "risc0.Output"

pub const A0_BIGINT: BigInt<4> = BigInt::new([162754123530195662, 1949396425256203034, 0, 0]);
pub const A0_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> = Fr::new(A0_BIGINT);

pub const A1_BIGINT: BigInt<4> = BigInt::new([2457364108815709557, 2960371475104660934, 0, 0]);
pub const A1_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> = Fr::new(A1_BIGINT);

pub const BN_254_CONTROL_ID_BIGINT: BigInt<4> = BigInt::new([
    10066737433256753856,
    15970898588890169697,
    12996428817291790227,
    307492062473808767,
]);
pub const BN_254_CONTROL_ID_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> =
    Fr::new(BN_254_CONTROL_ID_BIGINT);

pub const PREPARED_VK: &[u8] = include_bytes!("bin/prepared_vk.bin");

pub const TEST_PREPARED_VK: &[u8] = include_bytes!("bin/test_prepared_vk.bin");

#[cfg(feature = "use-test-vk")]
pub fn get_prepared_vk() -> &'static [u8] {
    TEST_PREPARED_VK
}

#[cfg(not(feature = "use-test-vk"))]
pub fn get_prepared_vk() -> &'static [u8] {
    PREPARED_VK
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use risc0_zkvm::Digest;

    use crate::bridge_circuit::constants::{A0_BIGINT, A1_BIGINT};

    // This test checks that the A0 and A1 constants match the expected values derived from the control root
    // of the Groth16 verifier parameters. If they do not match, it indicates that the constants need to be updated
    // in the `constants.rs` file. This is important because the A0 and A1 constants are used in the bridge circuit to verify the Groth16
    // proof, and any mismatch could lead to incorrect verification results.
    #[test]
    fn test_a0_and_a1() {
        let verifier_context = risc0_zkvm::VerifierContext::default();
        let params = verifier_context
            .groth16_verifier_parameters
            .as_ref()
            .unwrap();
        let (a0, a1) = split_digest(params.control_root);

        let a0_bigint = a0.into_bigint();
        let a1_bigint = a1.into_bigint();

        assert_eq!((a0_bigint, a1_bigint), (A0_BIGINT, A1_BIGINT),
            "A0 and A1 do not match the expected values, please update the a0 and a1 constants in constants.rs. a0: {:?}, a1: {:?}",
            a0_bigint.0, a1_bigint.0);
    }

    // This is the exact same implementation as in risc0_groth16, but we need to re-implement it here to change
    // the return type. Please check the original implementation each time risc0 version is updated.
    fn split_digest(d: Digest) -> (Fr, Fr) {
        let big_endian: Vec<u8> = d.as_bytes().to_vec().iter().rev().cloned().collect();
        let middle = big_endian.len() / 2;
        let (b, a) = big_endian.split_at(middle);
        (
            Fr::from_be_bytes_mod_order(&from_u256_hex(&hex::encode(a))),
            Fr::from_be_bytes_mod_order(&from_u256_hex(&hex::encode(b))),
        )
    }

    fn from_u256_hex(value: &str) -> Vec<u8> {
        to_fixed_array(hex::decode(value).unwrap()).to_vec()
    }

    fn to_fixed_array(input: Vec<u8>) -> [u8; 32] {
        let mut fixed_array = [0u8; 32];
        let start = core::cmp::max(32, input.len()) - core::cmp::min(32, input.len());
        fixed_array[start..].copy_from_slice(&input[input.len().saturating_sub(32)..]);
        fixed_array
    }
}
