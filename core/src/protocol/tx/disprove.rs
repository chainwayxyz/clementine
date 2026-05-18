//! Disprove transaction.
//!
//! This transaction spends the kickoff disprove output together with round
//! collateral when a faulty BitVM assertion or additional disprove path is
//! proven on-chain.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{non_ephemeral_anchor_output_utxo, round_kickoff_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::{kickoff::KickoffOutput, round::RoundOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisproveInput {
    Disprove,
    CollateralInRound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisproveOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<DisproveInput, DisproveOutput> {
    TxSpec::new(
        bitcoin::transaction::Version::TWO,
        bitcoin::absolute::LockTime::ZERO,
        vec![DisproveInput::Disprove, DisproveInput::CollateralInRound],
        vec![DisproveOutput::Anchor],
    )
}

impl DisproveInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            Self::Disprove => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Disprove,
                DEFAULT_SEQUENCE,
            )
            .reveal(),
            Self::CollateralInRound => InputSpec::parent(
                TransactionType::Round(round),
                RoundOutput::RemainingCollateral,
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Operator, TapSighashType::Default),
        }
    }
}

impl From<DisproveInput> for Input {
    fn from(value: DisproveInput) -> Self {
        Input::Disprove(value)
    }
}

impl DisproveOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        _datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            DisproveOutput::Anchor => Ok(non_ephemeral_anchor_output_utxo()),
        }
    }
}

impl From<DisproveOutput> for Output {
    fn from(value: DisproveOutput) -> Self {
        Output::Disprove(value)
    }
}
