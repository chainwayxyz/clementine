use crate::errors::BridgeError;
use bitcoin::{Amount, Network};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;

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
/// [`ProtocolParamset`] reference. Refers to a defined constant paramset in this module or a defined external source.
///
/// See: [`MAINNET_PARAMSET`], [`REGTEST_PARAMSET`], [`TESTNET_PARAMSET`].
pub enum ProtocolParamsetName {
    Mainnet,
    Regtest,
    Testnet4,
    Signet,
    /// Explicitly read from environment variables and exit with error if not set
    Env,
    /// Read from external config file and exit with error if not set
    File,
}

impl FromStr for ProtocolParamsetName {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(ProtocolParamsetName::Mainnet),
            "regtest" => Ok(ProtocolParamsetName::Regtest),
            "testnet4" => Ok(ProtocolParamsetName::Testnet4),
            "signet" => Ok(ProtocolParamsetName::Signet),
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
            ProtocolParamsetName::Mainnet => write!(f, "mainnet"),
            ProtocolParamsetName::Regtest => write!(f, "regtest"),
            ProtocolParamsetName::Testnet4 => write!(f, "testnet4"),
            ProtocolParamsetName::Signet => write!(f, "signet"),
            ProtocolParamsetName::Env => write!(f, "env"),
            ProtocolParamsetName::File => write!(f, "file"),
        }
    }
}

impl From<ProtocolParamsetName> for &'static ProtocolParamset {
    fn from(name: ProtocolParamsetName) -> Self {
        match name {
            ProtocolParamsetName::Mainnet => &MAINNET_PARAMSET,
            ProtocolParamsetName::Regtest => &REGTEST_PARAMSET,
            ProtocolParamsetName::Testnet4 => &TESTNET4_PARAMSET,
            ProtocolParamsetName::Signet => &SIGNET_PARAMSET,
            ProtocolParamsetName::Env => &ENV_PARAMSET,
            ProtocolParamsetName::File => &FILE_PARAMSET,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
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
    /// Number of blocks for operator reimburse timelock (currently BLOCKS_PER_DAY * 2)
    ///
    /// Timelocks operator from sending the next Round Tx after the Ready to Reimburse Tx.
    pub operator_reimburse_timelock: u16,
    /// Number of blocks for watchtower challenge timeout timelock (currently BLOCKS_PER_WEEK * 2)
    pub watchtower_challenge_timeout_timelock: u16,
    /// Time to wait after a kickoff to send a watchtower challenge
    pub time_to_send_watchtower_challenge: u16,
    /// Time to wait before trying to disprove (so that you collect all operator challenge acks before disproving)
    pub time_to_disprove: u16,
    /// Amount of depth a block should have from the current head to be considered finalized
    pub finality_depth: u32,
    /// start height to sync the chain from, i.e. the height bridge was deployed
    pub start_height: u32,
}

pub const MAINNET_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Bitcoin,
    num_round_txs: 200,
    num_kickoffs_per_round: 200,
    num_signed_kickoffs: 5,
    bridge_amount: Amount::from_sat(1_000_000_000),
    kickoff_amount: Amount::from_sat(55_000),
    operator_challenge_amount: Amount::from_sat(200_000_000),
    collateral_funding_amount: Amount::from_sat(200_000_000),
    kickoff_blockhash_commit_length: 40,
    watchtower_challenge_bytes: 144,
    winternitz_log_d: WINTERNITZ_LOG_D,
    user_takes_after: 200,
    operator_challenge_timeout_timelock: BLOCKS_PER_WEEK,
    operator_challenge_nack_timelock: BLOCKS_PER_WEEK * 3,
    disprove_timeout_timelock: BLOCKS_PER_WEEK * 5,
    assert_timeout_timelock: BLOCKS_PER_WEEK * 4,
    operator_reimburse_timelock: BLOCKS_PER_DAY * 2,
    watchtower_challenge_timeout_timelock: BLOCKS_PER_WEEK * 2,
    time_to_send_watchtower_challenge: BLOCKS_PER_WEEK * 2 / 4 * 3,
    time_to_disprove: BLOCKS_PER_WEEK * 7 / 2, // 3.5 weeks
    finality_depth: 6,
    start_height: 1,
};

pub const REGTEST_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Regtest,
    num_round_txs: 2,
    num_kickoffs_per_round: 10,
    num_signed_kickoffs: 2,
    bridge_amount: Amount::from_sat(1_000_000_000),
    kickoff_amount: Amount::from_sat(55_000),
    operator_challenge_amount: Amount::from_sat(200_000_000),
    collateral_funding_amount: Amount::from_sat(200_000_000),
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
    time_to_disprove: 4 * BLOCKS_PER_HOUR * 4 + 4 * BLOCKS_PER_HOUR / 2,
    finality_depth: 0,
    start_height: 201,
};

pub const TESTNET4_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Testnet4,
    num_round_txs: 200,
    num_kickoffs_per_round: 200,
    num_signed_kickoffs: 5,
    bridge_amount: Amount::from_sat(10_000_000),
    kickoff_amount: Amount::from_sat(55_000),
    operator_challenge_amount: Amount::from_sat(200_000_000),
    collateral_funding_amount: Amount::from_sat(200_000_000),
    kickoff_blockhash_commit_length: 40,
    watchtower_challenge_bytes: 144,
    winternitz_log_d: WINTERNITZ_LOG_D,
    user_takes_after: 200,
    operator_challenge_timeout_timelock: BLOCKS_PER_WEEK,
    operator_challenge_nack_timelock: BLOCKS_PER_WEEK * 3,
    disprove_timeout_timelock: BLOCKS_PER_WEEK * 5,
    assert_timeout_timelock: BLOCKS_PER_WEEK * 4,
    operator_reimburse_timelock: BLOCKS_PER_DAY * 2,
    watchtower_challenge_timeout_timelock: BLOCKS_PER_WEEK * 2,
    time_to_send_watchtower_challenge: BLOCKS_PER_WEEK * 2 / 4 * 3,
    time_to_disprove: BLOCKS_PER_WEEK * 7 / 2, // 3.5 weeks
    finality_depth: 60,
    start_height: 1,
};

pub const SIGNET_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Signet,
    num_round_txs: 2,
    num_kickoffs_per_round: 10,
    num_signed_kickoffs: 2,
    bridge_amount: Amount::from_sat(1_000_000_000),
    kickoff_amount: Amount::from_sat(55_000),
    operator_challenge_amount: Amount::from_sat(200_000_000),
    collateral_funding_amount: Amount::from_sat(200_000_000),
    kickoff_blockhash_commit_length: 40,
    watchtower_challenge_bytes: 144,
    winternitz_log_d: WINTERNITZ_LOG_D,
    user_takes_after: 200,
    operator_challenge_timeout_timelock: BLOCKS_PER_DAY,
    operator_challenge_nack_timelock: BLOCKS_PER_DAY * 3,
    disprove_timeout_timelock: BLOCKS_PER_DAY * 5,
    assert_timeout_timelock: BLOCKS_PER_DAY * 4,
    operator_reimburse_timelock: BLOCKS_PER_HOUR * 2,
    watchtower_challenge_timeout_timelock: BLOCKS_PER_DAY * 2,
    time_to_send_watchtower_challenge: BLOCKS_PER_DAY * 3 / 2,
    time_to_disprove: BLOCKS_PER_DAY * 4 + BLOCKS_PER_DAY / 2,
    finality_depth: 1,
    start_height: 201,
};

lazy_static! {
    pub static ref FILE_PARAMSET: Arc<ProtocolParamset> = {
        let config_path = std::env::var("PROTOCOL_CONFIG_PATH")
            .unwrap_or_else(|_| "protocol_params.toml".to_string());

        match ProtocolParamset::from_toml_file(&config_path) {
            Ok(params) => Arc::new(params),
            Err(e) => {
                eprintln!(
                    "Failed to load protocol params from {}: {}. Using regtest defaults.",
                    config_path, e
                );
                Arc::new(REGTEST_PARAMSET)
            }
        }
    };
    pub static ref ENV_PARAMSET: Arc<ProtocolParamset> = {
        match ProtocolParamset::from_env() {
            Ok(params) => Arc::new(params),
            Err(e) => {
                eprintln!(
                    "Failed to load protocol params from env: {}. Using regtest defaults.",
                    e
                );
                Arc::new(REGTEST_PARAMSET)
            }
        }
    };
}

impl ProtocolParamset {
    fn from_toml_file(path: &str) -> Result<Self, BridgeError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| BridgeError::Error(format!("Failed to read config file: {}", e)))?;

        let paramset: Self = toml::from_str(&contents)
            .map_err(|e| BridgeError::Error(format!("Failed to parse TOML: {}", e)))?;

        Ok(paramset)
    }
}
