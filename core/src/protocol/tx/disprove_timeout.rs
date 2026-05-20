//! Disprove-timeout transaction.
//!
//! This transaction is sent if the operator's asserted proof is not disproved in
//! time, enabling the operator to reimburse itself later.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisproveTimeoutInput {
    Disprove,
    KickoffFinalizer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisproveTimeoutOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<DisproveTimeoutInput, DisproveTimeoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            DisproveTimeoutInput::Disprove,
            DisproveTimeoutInput::KickoffFinalizer,
        ],
        vec![DisproveTimeoutOutput::Anchor],
    )
}

impl DisproveTimeoutInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            Self::Disprove => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Disprove,
                bitcoin::Sequence::from_height(datasources.params().disprove_timeout_timelock),
            )
            .leaf(
                KickoffLeaf::DisproveTimeout,
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

impl From<DisproveTimeoutInput> for Input {
    fn from(value: DisproveTimeoutInput) -> Self {
        Input::DisproveTimeout(value)
    }
}

impl DisproveTimeoutOutput {
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

impl From<DisproveTimeoutOutput> for Output {
    fn from(value: DisproveTimeoutOutput) -> Self {
        Output::DisproveTimeout(value)
    }
}
