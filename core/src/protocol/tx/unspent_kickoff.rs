//! Unspent-kickoff transaction.
//!
//! This transaction spends an unused kickoff connector after its one-block
//! timeout, together with ready-to-reimburse collateral.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::{Sequence, TapSighashType};
use clementine_errors::BridgeError;

use super::ready_to_reimburse::ReadyToReimburseOutput;
use super::round::{RoundLeaf, RoundOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnspentKickoffInput {
    CollateralInReadyToReimburse,
    Kickoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnspentKickoffOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<UnspentKickoffInput, UnspentKickoffOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            UnspentKickoffInput::CollateralInReadyToReimburse,
            UnspentKickoffInput::Kickoff,
        ],
        vec![UnspentKickoffOutput::Anchor],
    )
}

impl UnspentKickoffInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            Self::CollateralInReadyToReimburse => InputSpec::parent(
                TransactionType::ReadyToReimburse(round),
                ReadyToReimburseOutput::Collateral,
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Operator, TapSighashType::Default),
            Self::Kickoff => InputSpec::parent(
                TransactionType::Round(round),
                RoundOutput::Kickoff(kickoff.0),
                Sequence::from_height(1),
            )
            .leaf(
                RoundLeaf::KickoffOneBlockTimeout,
                Actor::Operator,
                TapSighashType::Default,
            ),
        }
    }
}

impl From<UnspentKickoffInput> for Input {
    fn from(value: UnspentKickoffInput) -> Self {
        Input::UnspentKickoff(value)
    }
}

impl UnspentKickoffOutput {
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

impl From<UnspentKickoffOutput> for Output {
    fn from(value: UnspentKickoffOutput) -> Self {
        Output::UnspentKickoff(value)
    }
}
