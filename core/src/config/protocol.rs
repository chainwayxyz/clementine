use crate::config::env::read_string_from_env_then_parse;
use crate::constants::{MIN_TAPROOT_AMOUNT, NON_EPHEMERAL_ANCHOR_AMOUNT};
use crate::errors::BridgeError;
use bitcoin::{Amount, Network};
use eyre::Context;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::str::FromStr;

pub const BLOCKS_PER_HOUR: u16 = 6;

pub const BLOCKS_PER_DAY: u16 = BLOCKS_PER_HOUR * 24;

pub const BLOCKS_PER_WEEK: u16 = BLOCKS_PER_DAY * 7;

/// This is the log_d used across the codebase.
///
/// All protocol paramsets should use this value since it's used in the BitVM static.
pub const WINTERNITZ_LOG_D: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// A pre-defined paramset name that can be converted into a
/// [`ProtocolParamset`] reference.
///
/// See: [`REGTEST_PARAMSET`]
pub enum ProtocolParamsetName {
    // Pre-defined paramsets
    Regtest,
}

impl FromStr for ProtocolParamsetName {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "regtest" => Ok(ProtocolParamsetName::Regtest),
            _ => Err(BridgeError::ConfigError(format!(
                "Unknown paramset name: {}",
                s
            ))),
        }
    }
}

impl Display for ProtocolParamsetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolParamsetName::Regtest => write!(f, "regtest"),
        }
    }
}

impl From<ProtocolParamsetName> for &'static ProtocolParamset {
    fn from(name: ProtocolParamsetName) -> Self {
        match name {
            ProtocolParamsetName::Regtest => &REGTEST_PARAMSET,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
/// Protocol parameters that affect the transactions in the contract (which also
/// change the pre-calculated txids and sighashes).
///
/// These parameters are used when generating the transactions and changing them
/// will break compatibility between actors, making deposits impossible.  A
/// paramset is chosen by the actor by choosing a ParamsetName inside the
/// [`crate::config::BridgeConfig`].
pub struct ProtocolParamset {
    /// Bitcoin network to work on (mainnet, testnet, regtest).
    pub network: Network,
    /// Number of round transactions that the operator will create.
    pub num_round_txs: usize,
    /// Number of kickoff UTXOs per round transaction.
    pub num_kickoffs_per_round: usize,
    /// Number of kickoffs that are signed per round and deposit.
    /// There are num_kickoffs_per_round utxo's, but only num_signed_kickoffs are signed.
    pub num_signed_kickoffs: usize,
    /// Bridge deposit amount that users can deposit.
    pub bridge_amount: Amount,
    /// Amount allocated for each kickoff UTXO.
    pub kickoff_amount: Amount,
    /// Amount allocated for operator challenge transactions.
    pub operator_challenge_amount: Amount,
    /// Collateral funding amount for operators used to fund the round transaction chain.
    pub collateral_funding_amount: Amount,
    /// Length of the blockhash commitment in kickoff transactions.
    pub kickoff_blockhash_commit_length: u32,
    /// Total number of bytes of a watchtower challenge.
    pub watchtower_challenge_bytes: usize,
    /// Winternitz derivation log_d (shared for all WOTS commitments)
    /// Currently used in statics and thus cannot be different from [`WINTERNITZ_LOG_D`].
    pub winternitz_log_d: u32,
    /// Number of blocks after which user can take deposit back if deposit request fails.
    pub user_takes_after: u16,
    /// Number of blocks for operator challenge timeout timelock (currently BLOCKS_PER_WEEK)
    pub operator_challenge_timeout_timelock: u16,
    /// Number of blocks for operator challenge NACK timelock (currently BLOCKS_PER_WEEK * 3)
    pub operator_challenge_nack_timelock: u16,
    /// Number of blocks for disprove timeout timelock (currently BLOCKS_PER_WEEK * 5)
    pub disprove_timeout_timelock: u16,
    /// Number of blocks for assert timeout timelock (currently BLOCKS_PER_WEEK * 4)
    pub assert_timeout_timelock: u16,
    /// Number of blocks for latest blockhash timeout timelock (currently BLOCKS_PER_WEEK * 2.5)
    pub latest_blockhash_timeout_timelock: u16,
    /// Number of blocks for operator reimburse timelock (currently BLOCKS_PER_DAY * 2)
    /// Timelocks operator from sending the next Round Tx after the Ready to Reimburse Tx.
    pub operator_reimburse_timelock: u16,
    /// Number of blocks for watchtower challenge timeout timelock (currently BLOCKS_PER_WEEK * 2)
    pub watchtower_challenge_timeout_timelock: u16,
    /// Time to wait after a kickoff to send a watchtower challenge
    pub time_to_send_watchtower_challenge: u16,
    /// Amount of depth a block should have from the current head to be considered finalized
    pub finality_depth: u32,
    /// start height to sync the chain from, i.e. the height bridge was deployed
    pub start_height: u32,
    /// Genesis height to sync the header chain proofs from
    pub genesis_height: u32,
    /// Genesis chain state hash
    pub genesis_chain_state_hash: [u8; 32],
    /// Batch size of the header chain proofs
    pub header_chain_proof_batch_size: u32,
    /// Denotes if the bridge is non-standard, i.e. uses 0 sat outputs for round tx (except collateral) and kickoff outputs
    pub bridge_nonstandard: bool,
}

impl ProtocolParamset {
    pub fn from_toml_file(path: &Path) -> Result<Self, BridgeError> {
        let contents = fs::read_to_string(path).wrap_err("Failed to read config file")?;

        let paramset: Self = toml::from_str(&contents).wrap_err("Failed to parse TOML")?;

        Ok(paramset)
    }
    pub fn from_env() -> Result<Self, BridgeError> {
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
            time_to_send_watchtower_challenge: read_string_from_env_then_parse::<u16>(
                "TIME_TO_SEND_WATCHTOWER_CHALLENGE",
            )?,
            finality_depth: read_string_from_env_then_parse::<u32>("FINALITY_DEPTH")?,
            start_height: read_string_from_env_then_parse::<u32>("START_HEIGHT")?,
            genesis_height: read_string_from_env_then_parse::<u32>("GENESIS_HEIGHT")?,
            genesis_chain_state_hash: convert_hex_string_to_bytes(
                &read_string_from_env_then_parse::<String>("GENESIS_CHAIN_STATE_HASH")?,
            )?,
            header_chain_proof_batch_size: read_string_from_env_then_parse::<u32>(
                "HEADER_CHAIN_PROOF_BATCH_SIZE",
            )?,
            latest_blockhash_timeout_timelock: read_string_from_env_then_parse::<u16>(
                "LATEST_BLOCKHASH_TIMEOUT_TIMELOCK",
            )?,
            bridge_nonstandard: read_string_from_env_then_parse::<bool>("BRIDGE_NONSTANDARD")?,
        };

        Ok(config)
    }

    pub fn default_utxo_amount(&self) -> Amount {
        if self.bridge_nonstandard {
            Amount::from_sat(0)
        } else {
            MIN_TAPROOT_AMOUNT
        }
    }

    pub fn anchor_amount(&self) -> Amount {
        if self.bridge_nonstandard {
            Amount::from_sat(0)
        } else {
            NON_EPHEMERAL_ANCHOR_AMOUNT
        }
    }

    pub fn bridge_circuit_constant(&self) -> Result<&[u8; 32], BridgeError> {
        match self.network {
            Network::Regtest => {
                if cfg!(test) {
                    Ok(&REGTEST_TEST_BRIDGE_CIRCUIT_CONSTANT)
                } else {
                    Ok(&REGTEST_BRIDGE_CIRCUIT_CONSTANT)
                }
            }
            Network::Bitcoin => Ok(&MAINNET_BRIDGE_CIRCUIT_CONSTANT),
            Network::Testnet4 => Ok(&TESTNET4_BRIDGE_CIRCUIT_CONSTANT),
            Network::Signet => Ok(&SIGNET_BRIDGE_CIRCUIT_CONSTANT),
            _ => Err(BridgeError::UnsupportedNetwork),
        }
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

impl Default for ProtocolParamset {
    fn default() -> Self {
        REGTEST_PARAMSET
    }
}
impl Default for &'static ProtocolParamset {
    fn default() -> Self {
        &REGTEST_PARAMSET
    }
}

pub const REGTEST_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Regtest,
    num_round_txs: 2,
    num_kickoffs_per_round: 10,
    num_signed_kickoffs: 2,
    bridge_amount: Amount::from_sat(1_000_000_000),
    kickoff_amount: Amount::from_sat(0),
    operator_challenge_amount: Amount::from_sat(200_000_000),
    collateral_funding_amount: Amount::from_sat(99_000_000),
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
    time_to_send_watchtower_challenge: 4 * BLOCKS_PER_HOUR * 3 / 2,
    latest_blockhash_timeout_timelock: 4 * BLOCKS_PER_HOUR * 5 / 2,
    finality_depth: 5, // citrea e2e finality depth
    start_height: 190,
    genesis_height: 0,
    genesis_chain_state_hash: [
        95, 115, 2, 173, 22, 200, 189, 158, 242, 243, 190, 0, 200, 25, 154, 134, 249, 224, 186,
        134, 20, 132, 171, 180, 175, 95, 126, 69, 127, 140, 34, 22,
    ],
    header_chain_proof_batch_size: 100,
    bridge_nonstandard: true,
};

pub const REGTEST_TEST_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    16, 165, 165, 178, 32, 248, 209, 16, 92, 31, 153, 107, 141, 102, 225, 158, 199, 83, 245, 24,
    171, 230, 193, 32, 59, 236, 22, 2, 41, 185, 222, 133,
];

pub const REGTEST_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    79, 241, 161, 65, 181, 201, 37, 216, 193, 232, 57, 16, 152, 31, 86, 48, 45, 77, 112, 173, 255,
    226, 25, 172, 213, 193, 59, 122, 102, 30, 117, 45,
];

pub const SIGNET_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    112, 119, 243, 160, 211, 170, 28, 174, 180, 218, 196, 56, 148, 29, 104, 199, 160, 209, 21, 163,
    61, 149, 150, 19, 8, 231, 84, 105, 217, 166, 184, 169,
];
pub const MAINNET_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    145, 32, 114, 253, 244, 45, 28, 164, 21, 76, 186, 105, 70, 226, 68, 89, 26, 52, 95, 129, 8,
    177, 7, 219, 252, 9, 69, 15, 170, 123, 24, 180,
];
pub const TESTNET4_BRIDGE_CIRCUIT_CONSTANT: [u8; 32] = [
    137, 6, 214, 141, 25, 65, 169, 28, 110, 33, 201, 145, 9, 166, 6, 36, 170, 236, 246, 146, 211,
    71, 40, 208, 173, 78, 27, 32, 12, 200, 159, 95,
];

#[cfg(test)]
mod tests {
    use bridge_circuit_host::{
        bridge_circuit_host::{
            MAINNET_BRIDGE_CIRCUIT_ELF, REGTEST_BRIDGE_CIRCUIT_ELF, SIGNET_BRIDGE_CIRCUIT_ELF,
            TESTNET4_BRIDGE_CIRCUIT_ELF,
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
