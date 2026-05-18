//! Mini-assert transaction.
//!
//! These transactions commit individual BitVM assertions for the operator's
//! proof that it paid the withdrawal corresponding to the deposit.

use crate::builder::transaction::{op_return_txout, DataSources, TxCache, UnspentTxOut};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_assert_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::KickoffOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MiniAssertInput {
    Assert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MiniAssertOutput {
    Anchor,
    Padding,
}

pub(crate) fn spec() -> TxSpec<MiniAssertInput, MiniAssertOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![MiniAssertInput::Assert],
        vec![MiniAssertOutput::Anchor, MiniAssertOutput::Padding],
    )
}

impl MiniAssertInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff, assert_idx) = round_kickoff_assert_from(tx_type);
        match self {
            Self::Assert => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Assert(assert_idx),
                crate::builder::transaction::DEFAULT_SEQUENCE,
            )
            .reveal_with(Actor::Operator, TapSighashType::Default),
        }
    }
}

impl From<MiniAssertInput> for Input {
    fn from(value: MiniAssertInput) -> Self {
        Input::MiniAssert(value)
    }
}

impl MiniAssertOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            Self::Anchor => Ok(anchor_output_utxo(datasources)),
            Self::Padding => Ok(UnspentTxOut::from_partial(op_return_txout(b""))),
        }
    }
}

impl From<MiniAssertOutput> for Output {
    fn from(value: MiniAssertOutput) -> Self {
        Output::MiniAssert(value)
    }
}
