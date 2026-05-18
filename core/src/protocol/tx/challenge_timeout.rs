//! Challenge-timeout transaction.
//!
//! This transaction is sent if no challenge is submitted in time, allowing the
//! operator to claim the timeout path and continue toward reimbursement.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::{Sequence, TapSighashType};
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeTimeoutInput {
    Challenge,
    KickoffFinalizer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeTimeoutOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<ChallengeTimeoutInput, ChallengeTimeoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            ChallengeTimeoutInput::Challenge,
            ChallengeTimeoutInput::KickoffFinalizer,
        ],
        vec![ChallengeTimeoutOutput::Anchor],
    )
}

impl ChallengeTimeoutInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            Self::Challenge => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Challenge,
                Sequence::from_height(datasources.params().operator_challenge_timeout_timelock),
            )
            .leaf(
                KickoffLeaf::OperatorTimeout,
                Actor::Operator,
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
        }
    }
}

impl From<ChallengeTimeoutInput> for Input {
    fn from(value: ChallengeTimeoutInput) -> Self {
        Input::ChallengeTimeout(value)
    }
}

impl ChallengeTimeoutOutput {
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

impl From<ChallengeTimeoutOutput> for Output {
    fn from(value: ChallengeTimeoutOutput) -> Self {
        Output::ChallengeTimeout(value)
    }
}
