use crate::config::env::read_string_from_env_then_parse;
use crate::errors::BridgeError;
use bitcoin::{Amount, Network};
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

impl ProtocolParamset {
    pub fn from_toml_file(path: &Path) -> Result<Self, BridgeError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| BridgeError::Error(format!("Failed to read config file: {}", e)))?;

        let paramset: Self = toml::from_str(&contents)
            .map_err(|e| BridgeError::Error(format!("Failed to parse TOML: {}", e)))?;

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
            time_to_disprove: read_string_from_env_then_parse::<u16>("TIME_TO_DISPROVE")?,
            finality_depth: read_string_from_env_then_parse::<u32>("FINALITY_DEPTH")?,
            start_height: read_string_from_env_then_parse::<u32>("START_HEIGHT")?,
        };

        Ok(config)
    }
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
