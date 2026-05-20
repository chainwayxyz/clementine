//! Watchtower-challenge-timeout transaction.
//!
//! This transaction forces timeout resolution when a watchtower challenge is not
//! completed in time.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_watchtower_from};
use bitcoin::{Sequence, TapSighashType};
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchtowerChallengeTimeoutInput {
    WatchtowerChallenge,
    WatchtowerChallengeAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchtowerChallengeTimeoutOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<WatchtowerChallengeTimeoutInput, WatchtowerChallengeTimeoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            WatchtowerChallengeTimeoutInput::WatchtowerChallenge,
            WatchtowerChallengeTimeoutInput::WatchtowerChallengeAck,
        ],
        vec![WatchtowerChallengeTimeoutOutput::Anchor],
    )
}

impl WatchtowerChallengeTimeoutInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff, watchtower_idx) = round_kickoff_watchtower_from(tx_type);
        match self {
            Self::WatchtowerChallenge => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::WatchtowerChallenge(watchtower_idx),
                Sequence::from_height(datasources.params().watchtower_challenge_timeout_timelock),
            )
            .leaf(
                KickoffLeaf::WatchtowerChallenge,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::WatchtowerChallengeAck => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::WatchtowerChallengeAck(watchtower_idx),
                Sequence::from_height(datasources.params().watchtower_challenge_timeout_timelock),
            )
            .leaf(
                KickoffLeaf::WatchtowerAckTimeout,
                Actor::Verifier,
                TapSighashType::Default,
            ),
        }
    }
}

impl From<WatchtowerChallengeTimeoutInput> for Input {
    fn from(value: WatchtowerChallengeTimeoutInput) -> Self {
        Input::WatchtowerChallengeTimeout(value)
    }
}

impl WatchtowerChallengeTimeoutOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            Self::Anchor => Ok(anchor_output_utxo(datasources)),
        }
    }
}

impl From<WatchtowerChallengeTimeoutOutput> for Output {
    fn from(value: WatchtowerChallengeTimeoutOutput) -> Self {
        Output::WatchtowerChallengeTimeout(value)
    }
}
