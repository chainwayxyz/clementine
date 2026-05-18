//! Watchtower-challenge transaction.
//!
//! This transaction is sent by a watchtower to submit challenge commitment data
//! tied to a kickoff watchtower challenge output.

use crate::builder::transaction::{
    op_return_txout, DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_watchtower_from};
use bitcoin::script::PushBytesBuf;
use bitcoin::TapSighashType;
use clementine_errors::{BridgeError, TxError};

use super::kickoff::KickoffOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchtowerChallengeInput {
    Kickoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchtowerChallengeOutput {
    CommitData,
    Anchor,
}

pub(crate) fn spec() -> TxSpec<WatchtowerChallengeInput, WatchtowerChallengeOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![WatchtowerChallengeInput::Kickoff],
        vec![
            WatchtowerChallengeOutput::CommitData,
            WatchtowerChallengeOutput::Anchor,
        ],
    )
}

impl WatchtowerChallengeInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff, watchtower_idx) = round_kickoff_watchtower_from(tx_type);

        match self {
            Self::Kickoff => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::WatchtowerChallenge(watchtower_idx),
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Watchtower, TapSighashType::Default),
        }
    }
}

impl From<WatchtowerChallengeInput> for Input {
    fn from(value: WatchtowerChallengeInput) -> Self {
        Input::WatchtowerChallenge(value)
    }
}

impl WatchtowerChallengeOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let commit_data = datasources.watchtower_commit_data()?;

        match self {
            Self::CommitData => {
                let push_data = PushBytesBuf::try_from(commit_data.to_vec())
                    .map_err(|_| TxError::IncorrectWatchtowerChallengeDataLength)?;
                Ok(UnspentTxOut::from_partial(op_return_txout(push_data)))
            }
            Self::Anchor => Ok(anchor_output_utxo(datasources)),
        }
    }
}

impl From<WatchtowerChallengeOutput> for Output {
    fn from(value: WatchtowerChallengeOutput) -> Self {
        Output::WatchtowerChallenge(value)
    }
}
