//! Assert-timeout transaction.
//!
//! This transaction can be sent by anyone if the operator does not send the
//! corresponding assert in time, burning the round collateral and kickoff
//! finalizer.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_assert_from};
use bitcoin::{Sequence, TapSighashType};
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};
use super::round::RoundOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertTimeoutInput {
    Assert,
    KickoffFinalizer,
    CollateralInRound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertTimeoutOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<AssertTimeoutInput, AssertTimeoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            AssertTimeoutInput::Assert,
            AssertTimeoutInput::KickoffFinalizer,
            AssertTimeoutInput::CollateralInRound,
        ],
        vec![AssertTimeoutOutput::Anchor],
    )
}

impl AssertTimeoutInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff, assert_idx) = round_kickoff_assert_from(tx_type);
        match self {
            Self::Assert => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Assert(assert_idx),
                Sequence::from_height(datasources.params().assert_timeout_timelock),
            )
            .leaf(
                KickoffLeaf::AssertTimeout,
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

impl From<AssertTimeoutInput> for Input {
    fn from(value: AssertTimeoutInput) -> Self {
        Input::AssertTimeout(value)
    }
}

impl AssertTimeoutOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            AssertTimeoutOutput::Anchor => Ok(anchor_output_utxo(datasources)),
        }
    }
}

impl From<AssertTimeoutOutput> for Output {
    fn from(value: AssertTimeoutOutput) -> Self {
        Output::AssertTimeout(value)
    }
}
