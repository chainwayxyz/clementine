use ark_bn254::Fr;
use ark_ff::BigInt;
use hex_literal::hex;

pub static MAINNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("8786ce0ab42e73b33dfdc1e5ef390fda73d778612555a0093070d24b61a24ce3");
pub static TESTNET4_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("80d082e9377804b82ccd9c2f4ed6e1c2169a1d614f0a526eea524c6f78a0be9b");
pub static REGTEST_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("6a3bc935ea9bf5754a9b2dce236a5848e538fe00c7550a10d5435d17fcc15613");
pub static SIGNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("812754d7dbe35da55383d36d1428744d0e1b7e40a2f86e8671fb830489a45333");

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
