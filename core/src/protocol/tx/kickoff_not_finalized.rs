//! Kickoff-not-finalized transaction.
//!
//! This transaction is used if an operator sends ReadyToReimburse transaction
//! while not all kickoffs of the round are finalized, burning their collateral.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};
use super::ready_to_reimburse::ReadyToReimburseOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KickoffNotFinalizedInput {
    KickoffFinalizer,
    CollateralInReadyToReimburse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KickoffNotFinalizedOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<KickoffNotFinalizedInput, KickoffNotFinalizedOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            KickoffNotFinalizedInput::KickoffFinalizer,
            KickoffNotFinalizedInput::CollateralInReadyToReimburse,
        ],
        vec![KickoffNotFinalizedOutput::Anchor],
    )
}

impl KickoffNotFinalizedInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
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
            Self::CollateralInReadyToReimburse => InputSpec::parent(
                TransactionType::ReadyToReimburse(round),
                ReadyToReimburseOutput::Collateral,
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Operator, TapSighashType::Default),
        }
    }
}

impl From<KickoffNotFinalizedInput> for Input {
    fn from(value: KickoffNotFinalizedInput) -> Self {
        Input::KickoffNotFinalized(value)
    }
}

impl KickoffNotFinalizedOutput {
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

impl From<KickoffNotFinalizedOutput> for Output {
    fn from(value: KickoffNotFinalizedOutput) -> Self {
        Output::KickoffNotFinalized(value)
    }
}
