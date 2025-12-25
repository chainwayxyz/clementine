use crate::config::env::read_string_from_env_then_parse;
use bitcoin::{Amount, Network};
use bridge_circuit_host::utils::is_dev_mode;
use circuits_lib::bridge_circuit::constants::{
    DEVNET_LC_IMAGE_ID, MAINNET_LC_IMAGE_ID, REGTEST_LC_IMAGE_ID, TESTNET4_LC_IMAGE_ID,
};
pub use clementine_config::{
    ProtocolParamset, ProtocolParamsetName, BLOCKS_PER_HOUR, REGTEST_PARAMSET, WINTERNITZ_LOG_D,
};
use clementine_errors::BridgeError;
use eyre::Context;

pub const BLOCKS_PER_DAY: u16 = BLOCKS_PER_HOUR * 24;
pub const BLOCKS_PER_WEEK: u16 = BLOCKS_PER_DAY * 7;

pub trait ProtocolParamsetExt {
    fn bridge_circuit_constant(&self) -> Result<&'static [u8; 32], BridgeError>;
    fn get_lcp_image_id(&self) -> Result<[u8; 32], BridgeError>;
    fn from_env() -> Result<ProtocolParamset, BridgeError>;
}

impl ProtocolParamsetExt for ProtocolParamset {
    fn bridge_circuit_constant(&self) -> Result<&'static [u8; 32], BridgeError> {
        match self.network {
            Network::Regtest => {
                if is_dev_mode() {
                    Ok(&REGTEST_TEST_BRIDGE_CIRCUIT_CONSTANT)
                } else {
                    Ok(&REGTEST_BRIDGE_CIRCUIT_CONSTANT)
                }
            }
            Network::Bitcoin => Ok(&MAINNET_BRIDGE_CIRCUIT_CONSTANT),
            Network::Testnet4 => {
                if is_dev_mode() {
                    Ok(&TESTNET4_TEST_BRIDGE_CIRCUIT_CONSTANT)
                } else {
                    Ok(&TESTNET4_BRIDGE_CIRCUIT_CONSTANT)
                }
            }
            Network::Signet => {
                if is_dev_mode() {
                    Ok(&SIGNET_TEST_BRIDGE_CIRCUIT_CONSTANT)
                } else {
                    Ok(&SIGNET_BRIDGE_CIRCUIT_CONSTANT)
                }
            }
            _ => Err(BridgeError::UnsupportedNetwork),
        }
    }

    /// Get the light client proof image id for the network.
    fn get_lcp_image_id(&self) -> Result<[u8; 32], BridgeError> {
        Ok(match self.network {
            bitcoin::Network::Bitcoin => MAINNET_LC_IMAGE_ID,
            bitcoin::Network::Testnet4 => TESTNET4_LC_IMAGE_ID,
            bitcoin::Network::Signet => DEVNET_LC_IMAGE_ID,
            bitcoin::Network::Regtest => REGTEST_LC_IMAGE_ID,
            _ => return Err(eyre::eyre!("Unsupported Bitcoin network").into()),
        })
    }

    fn from_env() -> Result<Self, BridgeError> {
        let config = ProtocolParamset {
            network: read_string_from_env_then_parse::<Network>("NETWORK")?,
            num_round_txs: read_string_from_env_then_parse::<usize>("NUM_ROUND_TXS")?,
            num_kickoffs_per_round: read_string_from_env_then_parse::<usize>(
                "NUM_KICKOFFS_PER_ROUND",
            )?,
            num_signed_kickoffs: read_string_from_env_then_parse::<usize>("NUM_SIGNED_KICKOFFS")?,
            bridge_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "BRIDGE_AMOUNT",
            )?),
            kickoff_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "KICKOFF_AMOUNT",
            )?),
            operator_challenge_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "OPERATOR_CHALLENGE_AMOUNT",
            )?),
            collateral_funding_amount: Amount::from_sat(read_string_from_env_then_parse::<u64>(
                "COLLATERAL_FUNDING_AMOUNT",
            )?),
            kickoff_blockhash_commit_length: read_string_from_env_then_parse::<u32>(
                "KICKOFF_BLOCKHASH_COMMIT_LENGTH",
            )?,
            watchtower_challenge_bytes: read_string_from_env_then_parse::<usize>(
                "WATCHTOWER_CHALLENGE_BYTES",
            )?,
            winternitz_log_d: read_string_from_env_then_parse::<u32>("WINTERNITZ_LOG_D")?,
            user_takes_after: read_string_from_env_then_parse::<u16>("USER_TAKES_AFTER")?,
            operator_challenge_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "OPERATOR_CHALLENGE_TIMEOUT_TIMELOCK",
            )?,
            operator_challenge_nack_timelock: read_string_from_env_then_parse::<u16>(
                "OPERATOR_CHALLENGE_NACK_TIMELOCK",
            )?,
            disprove_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "DISPROVE_TIMEOUT_TIMELOCK",
            )?,
            assert_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "ASSERT_TIMEOUT_TIMELOCK",
            )?,
            operator_reimburse_timelock: read_string_from_env_then_parse::<u16>(
                "OPERATOR_REIMBURSE_TIMELOCK",
            )?,
            watchtower_challenge_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "WATCHTOWER_CHALLENGE_TIMEOUT_TIMELOCK",
            )?,
            finality_depth: read_string_from_env_then_parse::<u32>("FINALITY_DEPTH")?,
            start_height: read_string_from_env_then_parse::<u32>("START_HEIGHT")?,
            genesis_height: read_string_from_env_then_parse::<u32>("GENESIS_HEIGHT")?,
            genesis_chain_state_hash: convert_hex_string_to_bytes(
                &read_string_from_env_then_parse::<String>("GENESIS_CHAIN_STATE_HASH")?,
            )?,
            latest_blockhash_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "LATEST_BLOCKHASH_TIMEOUT_TIMELOCK",
            )?,
            bridge_nonstandard: read_string_from_env_then_parse::<bool>("BRIDGE_NONSTANDARD")?,
        };

        if config.finality_depth < 1 {
            return Err(BridgeError::ConfigError(
                "Finality depth must be at least 1".to_string(),
            ));
        }

        Ok(config)
    }
}

fn convert_hex_string_to_bytes(hex: &str) -> Result<[u8; 32], BridgeError> {
    let hex_decode = hex::decode(hex).wrap_err("Failed to decode hex string")?;
    let hex_bytes: [u8; 32] = hex_decode
        .as_slice()
        .try_into()
        .wrap_err("Hex string is not 32 bytes")?;
    Ok(hex_bytes)
}

#[cfg(test)]
pub const TESTNET4_TEST_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Testnet4,
    num_round_txs: 2,
    num_kickoffs_per_round: 10,
    num_signed_kickoffs: 2,
    bridge_amount: Amount::from_sat(1_000_000),
    kickoff_amount: Amount::from_sat(0),
    operator_challenge_amount: Amount::from_sat(200_000),
    collateral_funding_amount: Amount::from_sat(99_000),
    watchtower_challenge_bytes: 144,
    kickoff_blockhash_commit_length: 40,
    winternitz_log_d: WINTERNITZ_LOG_D,
    user_takes_after: 200,
    operator_challenge_timeout_timelock: 4 * BLOCKS_PER_HOUR,
    operator_challenge_nack_timelock: 4 * BLOCKS_PER_HOUR * 3,
    disprove_timeout_timelock: 4 * BLOCKS_PER_HOUR * 5,
    assert_timeout_timelock: 4 * BLOCKS_PER_HOUR * 4,
    operator_reimburse_timelock: 2,
    watchtower_challenge_timeout_timelock: 4 * BLOCKS_PER_HOUR * 2,
    latest_blockhash_timeout_timelock: 4 * BLOCKS_PER_HOUR * 5 / 2,
    finality_depth: 1,
    start_height: 92700,
    genesis_height: 92700,
    genesis_chain_state_hash: [
        0xe4, 0xe1, 0x28, 0xa8, 0x99, 0xaf, 0xee, 0xb1, 0x85, 0x5b, 0x4a, 0xb7, 0x2e, 0x4d, 0x88,
        0x50, 0xab, 0x35, 0x1b, 0xde, 0xf9, 0x4f, 0xc2, 0x78, 0xe8, 0x5c, 0x13, 0x11, 0xe2, 0x72,
        0xfe, 0x6a,
    ],
    bridge_nonstandard: true,
};

pub const REGTEST_TEST_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    114, 212, 219, 106, 251, 50, 248, 9, 2, 194, 84, 239, 229, 92, 195, 40, 218, 21, 55, 242, 230,
    201, 145, 209, 251, 25, 77, 124, 129, 131, 194, 20,
];

pub const REGTEST_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    233, 84, 200, 234, 120, 196, 185, 119, 174, 126, 140, 238, 189, 210, 149, 97, 161, 4, 229, 219,
    47, 124, 117, 197, 89, 165, 120, 138, 221, 74, 157, 71,
];

pub const SIGNET_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    73, 219, 48, 6, 223, 104, 179, 207, 180, 104, 112, 231, 210, 2, 0, 47, 87, 166, 183, 168, 211,
    250, 76, 145, 200, 214, 169, 135, 151, 47, 202, 184,
];

pub const SIGNET_TEST_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    234, 217, 1, 13, 50, 162, 237, 187, 139, 172, 117, 214, 39, 142, 252, 26, 47, 173, 67, 109, 98,
    47, 59, 121, 185, 133, 184, 164, 241, 44, 113, 58,
];

pub const MAINNET_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    129, 78, 18, 124, 221, 80, 148, 108, 252, 53, 139, 39, 96, 60, 162, 140, 241, 131, 111, 46, 52,
    145, 169, 103, 131, 115, 17, 113, 68, 193, 151, 45,
];

pub const TESTNET4_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    123, 6, 8, 84, 79, 122, 249, 123, 48, 241, 129, 10, 215, 65, 243, 68, 174, 66, 239, 146, 1, 75,
    168, 108, 46, 59, 223, 127, 125, 127, 97, 90,
];

pub const TESTNET4_TEST_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    83, 191, 166, 41, 241, 95, 11, 84, 148, 1, 21, 128, 190, 167, 207, 165, 143, 209, 232, 169,
    211, 120, 188, 115, 219, 48, 108, 224, 129, 254, 54, 214,
];

#[cfg(test)]
mod tests {
    use bridge_circuit_host::{
        bridge_circuit_host::{
            MAINNET_BRIDGE_CIRCUIT_ELF, REGTEST_BRIDGE_CIRCUIT_ELF, SIGNET_BRIDGE_CIRCUIT_ELF,
            SIGNET_BRIDGE_CIRCUIT_ELF_TEST, TESTNET4_BRIDGE_CIRCUIT_ELF,
            TESTNET4_BRIDGE_CIRCUIT_ELF_TEST,
        },
        utils::calculate_succinct_output_prefix,
    };
    use circuits_lib::{
        bridge_circuit::constants::{
            MAINNET_WORK_ONLY_METHOD_ID, REGTEST_WORK_ONLY_METHOD_ID, SIGNET_WORK_ONLY_METHOD_ID,
            TESTNET4_WORK_ONLY_METHOD_ID,
        },
        common::constants::{
            MAINNET_HEADER_CHAIN_METHOD_ID, REGTEST_HEADER_CHAIN_METHOD_ID,
            SIGNET_HEADER_CHAIN_METHOD_ID, TESTNET4_HEADER_CHAIN_METHOD_ID,
        },
    };
    use risc0_zkvm::compute_image_id;

    use bridge_circuit_host::bridge_circuit_host::{
        MAINNET_HEADER_CHAIN_ELF, MAINNET_WORK_ONLY_ELF, REGTEST_HEADER_CHAIN_ELF,
        REGTEST_WORK_ONLY_ELF, SIGNET_HEADER_CHAIN_ELF, SIGNET_WORK_ONLY_ELF,
        TESTNET4_HEADER_CHAIN_ELF, TESTNET4_WORK_ONLY_ELF,
    };

    use super::*;

    #[test]
    fn test_regtest_test_bridge_circuit_constant() {
        let regtest_bridge_elf =
            include_bytes!("../../../risc0-circuits/elfs/test-regtest-bridge-circuit-guest.bin");
        let regtest_bridge_circuit_method_id =
            compute_image_id(regtest_bridge_elf).expect("should compute image id");
        let calculated_regtest_bridge_circuit_constant =
            calculate_succinct_output_prefix(regtest_bridge_circuit_method_id.as_bytes());

        let regtest_bridge_circuit_constant = REGTEST_TEST_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_regtest_bridge_circuit_constant,
            regtest_bridge_circuit_constant,
            "You forgot to update regtest-(test) bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_regtest_bridge_circuit_constant,
            hex::encode(calculated_regtest_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_regtest_bridge_circuit_constant() {
        let regtest_bridge_elf = REGTEST_BRIDGE_CIRCUIT_ELF;
        let regtest_bridge_circuit_method_id =
            compute_image_id(regtest_bridge_elf).expect("should compute image id");
        let calculated_regtest_bridge_circuit_constant =
            calculate_succinct_output_prefix(regtest_bridge_circuit_method_id.as_bytes());

        let regtest_bridge_circuit_constant = REGTEST_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_regtest_bridge_circuit_constant,
            regtest_bridge_circuit_constant,
            "You forgot to update regtest bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_regtest_bridge_circuit_constant,
            hex::encode(calculated_regtest_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_mainnet_bridge_circuit_constant() {
        let mainnet_bridge_elf = MAINNET_BRIDGE_CIRCUIT_ELF;
        let mainnet_bridge_circuit_method_id =
            compute_image_id(mainnet_bridge_elf).expect("should compute image id");
        let calculated_mainnet_bridge_circuit_constant =
            calculate_succinct_output_prefix(mainnet_bridge_circuit_method_id.as_bytes());

        let mainnet_bridge_circuit_constant = MAINNET_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_mainnet_bridge_circuit_constant,
            mainnet_bridge_circuit_constant,
            "You forgot to update mainnet bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_mainnet_bridge_circuit_constant,
            hex::encode(calculated_mainnet_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_testnet4_bridge_circuit_constant() {
        let testnet4_bridge_elf = TESTNET4_BRIDGE_CIRCUIT_ELF;
        let testnet4_bridge_circuit_method_id =
            compute_image_id(testnet4_bridge_elf).expect("should compute image id");
        let calculated_testnet4_bridge_circuit_constant =
            calculate_succinct_output_prefix(testnet4_bridge_circuit_method_id.as_bytes());

        let testnet4_bridge_circuit_constant = TESTNET4_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_testnet4_bridge_circuit_constant,
            testnet4_bridge_circuit_constant,
            "You forgot to update testnet4 bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_testnet4_bridge_circuit_constant,
            hex::encode(calculated_testnet4_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_testnet4_test_bridge_circuit_constant() {
        let testnet4_bridge_elf = TESTNET4_BRIDGE_CIRCUIT_ELF_TEST;
        let testnet4_bridge_circuit_method_id =
            compute_image_id(testnet4_bridge_elf).expect("should compute image id");
        let calculated_testnet4_bridge_circuit_constant =
            calculate_succinct_output_prefix(testnet4_bridge_circuit_method_id.as_bytes());

        let testnet4_bridge_circuit_constant = TESTNET4_TEST_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_testnet4_bridge_circuit_constant,
            testnet4_bridge_circuit_constant,
            "You forgot to update testnet4-test bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_testnet4_bridge_circuit_constant,
            hex::encode(calculated_testnet4_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_signet_bridge_circuit_constant() {
        let signet_bridge_elf = SIGNET_BRIDGE_CIRCUIT_ELF;
        let signet_bridge_circuit_method_id =
            compute_image_id(signet_bridge_elf).expect("should compute image id");
        let calculated_signet_bridge_circuit_constant =
            calculate_succinct_output_prefix(signet_bridge_circuit_method_id.as_bytes());

        let signet_bridge_circuit_constant = SIGNET_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_signet_bridge_circuit_constant,
            signet_bridge_circuit_constant,
            "You forgot to update signet bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_signet_bridge_circuit_constant,
            hex::encode(calculated_signet_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_signet_test_bridge_circuit_constant() {
        let signet_bridge_elf = SIGNET_BRIDGE_CIRCUIT_ELF_TEST;
        let signet_bridge_circuit_method_id =
            compute_image_id(signet_bridge_elf).expect("should compute image id");
        let calculated_signet_bridge_circuit_constant =
            calculate_succinct_output_prefix(signet_bridge_circuit_method_id.as_bytes());

        let signet_bridge_circuit_constant = SIGNET_TEST_BRIDGE_CIRCUIT_CONSTANT;
        assert_eq!(
            calculated_signet_bridge_circuit_constant,
            signet_bridge_circuit_constant,
            "You forgot to update signet-test bridge_circuit_constant with the new method id. Please change it in these places: core/src/config/protocol.rs. The expected value is: {:?}, hex format: {:?}",
            calculated_signet_bridge_circuit_constant,
            hex::encode(calculated_signet_bridge_circuit_constant)
        );
    }

    #[test]
    fn test_header_chain_method_ids() {
        let networks = [
            (
                MAINNET_HEADER_CHAIN_ELF,
                MAINNET_HEADER_CHAIN_METHOD_ID,
                "mainnet",
            ),
            (
                TESTNET4_HEADER_CHAIN_ELF,
                TESTNET4_HEADER_CHAIN_METHOD_ID,
                "testnet4",
            ),
            (
                SIGNET_HEADER_CHAIN_ELF,
                SIGNET_HEADER_CHAIN_METHOD_ID,
                "signet",
            ),
            (
                REGTEST_HEADER_CHAIN_ELF,
                REGTEST_HEADER_CHAIN_METHOD_ID,
                "regtest",
            ),
        ];

        for (elf, method_id, network) in networks.into_iter() {
            let header_chain_circuit_method_id = compute_image_id(elf);
            assert_eq!(
                header_chain_circuit_method_id.expect("should compute image id").as_words(),
                method_id,
                "Header chain method ID mismatch for {network}, please update the constant here: circuits-lib/src/common/constants.rs",
            );
        }
    }

    #[test]
    fn test_work_only_method_ids() {
        let networks = [
            (
                MAINNET_WORK_ONLY_ELF,
                MAINNET_WORK_ONLY_METHOD_ID,
                "mainnet",
            ),
            (
                TESTNET4_WORK_ONLY_ELF,
                TESTNET4_WORK_ONLY_METHOD_ID,
                "testnet4",
            ),
            (SIGNET_WORK_ONLY_ELF, SIGNET_WORK_ONLY_METHOD_ID, "signet"),
            (
                REGTEST_WORK_ONLY_ELF,
                REGTEST_WORK_ONLY_METHOD_ID,
                "regtest",
            ),
        ];

        for (elf, method_id, network) in networks.into_iter() {
            let work_only_circuit_method_id =
                compute_image_id(elf).expect("should compute image id");
            let current_method_id = work_only_circuit_method_id.as_bytes();
            assert_eq!(
                current_method_id,
                method_id,
                "Work only method ID mismatch for {network}, please update the constant here: circuits-lib/src/bridge_circuit/constants.rs. Hex format of correct value: {:?}",
                hex::encode(current_method_id)
            );
        }
    }
}
