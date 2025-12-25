//! Protocol parameters for the clementine bridge.
//!
//! This module contains the protocol paramset definitions that control bridge behavior.

use bitcoin::{Amount, Network};
use clementine_errors::BridgeError;
use eyre::Context;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// Blocks per hour on average for Bitcoin (6 blocks per hour).
pub const BLOCKS_PER_HOUR: u16 = 6;

/// This is the log_d used across the codebase.
///
/// All protocol paramsets should use this value since it's used in the BitVM static.
pub const WINTERNITZ_LOG_D: u32 = 4;

/// The minimum possible amount that a UTXO can have when created into a Taproot address.
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330);

/// The amount of the non-ephemeral P2A anchor output.
pub const NON_EPHEMERAL_ANCHOR_AMOUNT: Amount = Amount::from_sat(240);

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
                "Unknown paramset name: {s}"
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
/// [`BridgeConfig`].
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
    /// Amount of depth a block should have from the current head to be considered finalized
    /// Also means finality_confirmations, how many confirmations are needed for a block to be considered finalized
    /// The chain tip has 1 confirmation. Minimum value should be 1.
    pub finality_depth: u32,
    /// start height to sync the chain from, i.e. the height bridge was deployed
    pub start_height: u32,
    /// Genesis height to sync the header chain proofs from
    pub genesis_height: u32,
    /// Genesis chain state hash
    pub genesis_chain_state_hash: [u8; 32],
    /// Denotes if the bridge is non-standard, i.e. uses 0 sat outputs for round tx (except collateral) and kickoff outputs
    pub bridge_nonstandard: bool,
}

impl ProtocolParamset {
    /// Parse a `ProtocolParamset` from a TOML file.
    pub fn from_toml_file(path: &Path) -> Result<Self, BridgeError> {
        let contents = fs::read_to_string(path).wrap_err("Failed to read config file")?;

        let paramset: Self = toml::from_str(&contents).wrap_err("Failed to parse TOML")?;
        if paramset.finality_depth < 1 {
            return Err(BridgeError::ConfigError(
                "Finality depth must be at least 1".to_string(),
            ));
        }

        Ok(paramset)
    }

    /// Returns the default UTXO amount based on whether the bridge is non-standard.
    pub fn default_utxo_amount(&self) -> Amount {
        if self.bridge_nonstandard {
            Amount::from_sat(0)
        } else {
            MIN_TAPROOT_AMOUNT
        }
    }

    /// Returns the anchor amount based on whether the bridge is non-standard.
    pub fn anchor_amount(&self) -> Amount {
        if self.bridge_nonstandard {
            Amount::from_sat(0)
        } else {
            NON_EPHEMERAL_ANCHOR_AMOUNT
        }
    }

    /// Checks if a block is finalized. In clementine and citrea, finality depth means the amount of confirmations needed for a block to be considered finalized.
    /// The chain tip has 1 confirmation.
    pub fn is_block_finalized(&self, block_height: u32, chain_tip_height: u32) -> bool {
        if block_height > chain_tip_height {
            return false;
        }

        chain_tip_height - block_height + 1 >= self.finality_depth
    }

    /// Returns true if this is a regtest network.
    pub fn is_regtest(&self) -> bool {
        self.network == Network::Regtest
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

/// The default regtest protocol paramset.
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
    latest_blockhash_timeout_timelock: 4 * BLOCKS_PER_HOUR * 5 / 2,
    finality_depth: 5, // citrea e2e finality depth
    start_height: 190,
    genesis_height: 0,
    genesis_chain_state_hash: [
        95, 115, 2, 173, 22, 200, 189, 158, 242, 243, 190, 0, 200, 25, 154, 134, 249, 224, 186,
        134, 20, 132, 171, 180, 175, 95, 126, 69, 127, 140, 34, 22,
    ],
    bridge_nonstandard: true,
};
