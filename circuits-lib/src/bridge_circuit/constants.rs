use ark_bn254::Fr;
use ark_ff::BigInt;
use hex_literal::hex;

pub static MAINNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("f0c49d00c66be8f94bfa268502a2b1f4780e5b903b7219196491044fc471b72f");
pub static TESTNET4_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("ad8f1f9bd52df3429eb82ccba2c431006b9af8cdfa711c6debc4af3bfc5d4647");
pub static REGTEST_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("5597796a454e2499315e2a177037c886094569c8d7fe5e8253c76c5027821852");
pub static SIGNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("2e973d14ff0830bc6567c2021ecc4e2e165fc81b6816c1909eccf7aa31f97ae4");

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
