use ark_bn254::Fr;
use ark_ff::BigInt;
use hex_literal::hex;

/// Work-only circuit method IDs for different networks.
pub static MAINNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("bfbc9b0a0c8af2ea0c2b8e54b0f06b9c7d862dc944ab0d95e7c18308fbc5b793");
pub static TESTNET4_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("fd06dbc93ad27e3997f6cf7d754b7c30df3c606b929bca93554b204d922de51b");
pub static REGTEST_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("948e25c4707a0ea2bedd1e6ef84f1bc8f03669c73882d2a19b404d3cd45d013a");
pub static SIGNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("962ae374238fe686d2212409143c92793eb838d6dc0372880845277710ff1401");

// GROTH16 RELATED CONSTANTS
pub static POST_STATE: [u8; 32] =
    hex_literal::hex!("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2");
pub static INPUT: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static ASSUMPTIONS: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
pub static CLAIM_TAG: [u8; 32] =
    hex_literal::hex!("cb1fefcd1f2d9a64975cbbbf6e161e2914434b0cbb9960b84df5d717e86b48af"); // hash of "risc0.ReceiptClaim"
pub static OUTPUT_TAG: [u8; 32] =
    hex_literal::hex!("77eafeb366a78b47747de0d7bb176284085ff5564887009a5be63da32d3559d4"); // hash of "risc0.Output"

pub const A0_BIGINT: BigInt<4> = BigInt::new([3584412468423285388, 5573840904707615506, 0, 0]);
pub const A0_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> = Fr::new(A0_BIGINT);

pub const A1_BIGINT: BigInt<4> = BigInt::new([3118573868620133879, 7567222285189782870, 0, 0]);
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
