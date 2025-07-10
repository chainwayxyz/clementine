use ark_bn254::Fr;
use ark_ff::BigInt;
use hex_literal::hex;

/// Work-only circuit method IDs for different networks.
pub static MAINNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("52fb341c88914a0373ceaf24d05cbd7d25a985c1d5ad43b89481272d87078a54");
pub static TESTNET4_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("ac53f8eec3de637a71c0054a97fbb70d90b70986d459dc82bc8ad5ebba2ba992");
pub static REGTEST_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("0fa79aa35c0dad5d9bfd3cc9cacb2e59a886633b5cd3a125225c39de8bef6186");
pub static SIGNET_WORK_ONLY_METHOD_ID: [u8; 32] =
    hex!("fdbba6bf1e3cc9b0cac853ea7ea9e5abdab3807b613f23ccd1553b3db05eba13");

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

pub const A0_BIGINT: BigInt<4> = BigInt::new([3642024781819757448, 7056707323904088903, 0, 0]);
pub const A0_ARK: ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4> = Fr::new(A0_BIGINT);

pub const A1_BIGINT: BigInt<4> = BigInt::new([2320229930753554331, 6984597893759827489, 0, 0]);
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
