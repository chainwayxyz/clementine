use bitcoin::{Amount, Network};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// A pre-defined paramset name that can be converted into a
/// [`ProtocolParamset`] reference. Refers to a defined constant paramset in this module.
///
/// See: [`MAINNET_PARAMSET`], [`REGTEST_PARAMSET`], [`TESTNET_PARAMSET`].
pub enum ProtocolParamsetName {
    Mainnet,
    Regtest,
    Testnet,
}

impl From<ProtocolParamsetName> for &'static ProtocolParamset {
    fn from(name: ProtocolParamsetName) -> Self {
        match name {
            ProtocolParamsetName::Mainnet => &MAINNET_PARAMSET,
            ProtocolParamsetName::Regtest => &REGTEST_PARAMSET,
            ProtocolParamsetName::Testnet => &TESTNET_PARAMSET,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Protocol parameters that affect the transactions in the contract (which also
/// change the pre-calculated txids and sighashes).
///
/// These parameters are used when generating the transactions and changing them
/// will break compatibility between actors, making deposits impossible.  A
/// paramset is chosen by the actor by choosing a ParamsetName inside the
/// [`crate::config::BridgeConfig`].
pub struct ProtocolParamset {
    pub network: Network,
    pub num_round_txs: usize,
    pub num_kickoffs_per_round: usize,
    pub bridge_amount: Amount,
    pub kickoff_amount: Amount,
    pub operator_challenge_amount: Amount,
    pub collateral_funding_amount: Amount,
    pub kickoff_blockhash_commit_length: usize,
    pub watchtower_challenge_message_length: usize,
}

pub const MAINNET_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Bitcoin,
    num_round_txs: 2,
    bridge_amount: Amount::from_sat(1_000_000_000),
    kickoff_amount: Amount::from_sat(40_000),
    kickoff_blockhash_commit_length: 40,
    operator_challenge_amount: Amount::from_sat(200_000_000),
    watchtower_challenge_message_length: 480,
    num_kickoffs_per_round: 200,
    collateral_funding_amount: Amount::from_sat(200_000_000),
};

pub const REGTEST_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Regtest,
    num_round_txs: 2,
    bridge_amount: Amount::from_sat(1_000_000_000),
    kickoff_amount: Amount::from_sat(40_000),
    kickoff_blockhash_commit_length: 40,
    operator_challenge_amount: Amount::from_sat(200_000_000),
    watchtower_challenge_message_length: 480,
    num_kickoffs_per_round: 2,
    collateral_funding_amount: Amount::from_sat(200_000_000),
};

pub const TESTNET_PARAMSET: ProtocolParamset = ProtocolParamset {
    network: Network::Testnet,
    num_round_txs: 2,
    bridge_amount: Amount::from_sat(10_000_000),
    kickoff_amount: Amount::from_sat(40_000),
    kickoff_blockhash_commit_length: 40,
    operator_challenge_amount: Amount::from_sat(200_000_000),
    watchtower_challenge_message_length: 480,
    num_kickoffs_per_round: 2,
    collateral_funding_amount: Amount::from_sat(200_000_000),
};
