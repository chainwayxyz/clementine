//! Ready-to-reimburse transaction.
//!
//! This transaction rolls the remaining round collateral forward so the next
//! round can be chained and reimbursement connectors can be generated.

use crate::builder::transaction::{anchor_output, DataSources, TxCache, TxCacheExt, UnspentTxOut};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use bitcoin::TapSighashType;
use clementine_errors::{BridgeError, TxError};

use super::round::RoundOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadyToReimburseInput {
    CollateralInRound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadyToReimburseOutput {
    Collateral,
    Anchor,
}

pub(crate) fn spec() -> TxSpec<ReadyToReimburseInput, ReadyToReimburseOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![ReadyToReimburseInput::CollateralInRound],
        vec![
            ReadyToReimburseOutput::Collateral,
            ReadyToReimburseOutput::Anchor,
        ],
    )
}

impl ReadyToReimburseInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            Self::CollateralInRound => {
                let round = match tx_type {
                    TransactionType::ReadyToReimburse(round) => *round,
                    _ => unreachable!(
                        "ready_to_reimburse::ReadyToReimburseInput used with wrong tx_type"
                    ),
                };
                InputSpec::parent(
                    TransactionType::Round(round),
                    RoundOutput::RemainingCollateral,
                    crate::builder::transaction::DEFAULT_SEQUENCE,
                )
                .key_path(Actor::Operator, TapSighashType::Default)
            }
        }
    }
}

impl From<ReadyToReimburseInput> for Input {
    fn from(value: ReadyToReimburseInput) -> Self {
        Input::ReadyToReimburse(value)
    }
}

impl ReadyToReimburseOutput {
    pub(crate) fn materialize(
        self,
        tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let round = match tx_type {
            TransactionType::ReadyToReimburse(round) => *round,
            _ => return Err(TxError::InsufficientContext.into()),
        };
        let paramset = datasources.params();
        let parent = cache.get_required(TransactionType::Round(round))?;
        let prevout = parent.get_spendable_output(RoundOutput::RemainingCollateral)?;
        let prev_value = prevout.get_prevout().value;

        match self {
            Self::Collateral => Ok(UnspentTxOut::key_path(
                prev_value.checked_sub(paramset.anchor_amount()).ok_or(
                    BridgeError::ArithmeticOverflow(
                        "Insufficient funds while creating ready to reimburse tx",
                    ),
                )?,
                Some(datasources.operator()?.xonly_pk),
            )),
            Self::Anchor => Ok(UnspentTxOut::from_partial(anchor_output(
                paramset.anchor_amount(),
            ))),
        }
    }
}

impl From<ReadyToReimburseOutput> for Output {
    fn from(value: ReadyToReimburseOutput) -> Self {
        Output::ReadyToReimburse(value)
    }
}
