//! Operator-challenge-nack transaction.
//!
//! This transaction is used to penalize a malicious operator by burning round
//! collateral after the operator fails to acknowledge a watchtower challenge in
//! time.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_watchtower_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};
use super::round::RoundOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorChallengeNackInput {
    WatchtowerChallengeAck,
    KickoffFinalizer,
    CollateralInRound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorChallengeNackOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<OperatorChallengeNackInput, OperatorChallengeNackOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            OperatorChallengeNackInput::WatchtowerChallengeAck,
            OperatorChallengeNackInput::KickoffFinalizer,
            OperatorChallengeNackInput::CollateralInRound,
        ],
        vec![OperatorChallengeNackOutput::Anchor],
    )
}

impl OperatorChallengeNackInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff, watchtower_idx) = round_kickoff_watchtower_from(tx_type);
        match self {
            Self::WatchtowerChallengeAck => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::WatchtowerChallengeAck(watchtower_idx),
                bitcoin::Sequence::from_height(
                    datasources.params().operator_challenge_nack_timelock,
                ),
            )
            .leaf(
                KickoffLeaf::ChallengeNackTimeout,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::KickoffFinalizer => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Finalizer,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                KickoffLeaf::NofnSpend,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::CollateralInRound => InputSpec::parent(
                TransactionType::Round(round),
                RoundOutput::RemainingCollateral,
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Operator, TapSighashType::Default),
        }
    }
}

impl From<OperatorChallengeNackInput> for Input {
    fn from(value: OperatorChallengeNackInput) -> Self {
        Input::OperatorChallengeNack(value)
    }
}

impl OperatorChallengeNackOutput {
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

impl From<OperatorChallengeNackOutput> for Output {
    fn from(value: OperatorChallengeNackOutput) -> Self {
        Output::OperatorChallengeNack(value)
    }
}
