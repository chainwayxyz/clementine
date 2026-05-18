//! Burn-unused-kickoff-connectors transaction.
//!
//! This transaction burns unused kickoff connectors after the one-block timeout
//! passes, optionally returning change when the remainder is large enough.

use std::collections::HashSet;

use crate::builder::transaction::{anchor_output, DataSources, TxCache, TxCacheExt, UnspentTxOut};
use crate::constants::{MIN_TAPROOT_AMOUNT, NON_STANDARD_V3};
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use bitcoin::{Amount, TapSighashType, TxOut};
use clementine_errors::{BridgeError, TxError};
use eyre::eyre;

use super::round::{RoundLeaf, RoundOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BurnUnusedKickoffConnectorsInput {
    UnusedKickoffConnector(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BurnUnusedKickoffConnectorsOutput {
    Change,
    Anchor,
}

pub(crate) fn validate_indices(indices: &[usize], num_kickoffs: usize) -> Result<(), BridgeError> {
    if indices.is_empty() {
        return Err(TxError::EmptyBurnUnusedKickoffConnectors.into());
    }

    let mut seen = HashSet::new();
    for &idx in indices {
        if idx >= num_kickoffs {
            return Err(TxError::BurnUnusedKickoffConnectorIndexOutOfRange {
                index: idx,
                num_kickoffs,
            }
            .into());
        }

        if !seen.insert(idx) {
            return Err(TxError::DuplicateBurnUnusedKickoffConnector(idx).into());
        }
    }

    Ok(())
}

pub(crate) fn has_change_output(indices: &[usize], datasources: &impl DataSources) -> bool {
    let paramset = datasources.params();
    !paramset.bridge_nonstandard
        && paramset
            .kickoff_amount
            .checked_mul(indices.len() as u64)
            .is_some_and(|input_amount| {
                input_amount >= paramset.anchor_amount() + MIN_TAPROOT_AMOUNT
            })
}

pub(crate) fn spec(
    indices: &[usize],
    datasources: &impl DataSources,
) -> TxSpec<BurnUnusedKickoffConnectorsInput, BurnUnusedKickoffConnectorsOutput> {
    let mut inputs = vec![];
    for &idx in indices {
        inputs.push(BurnUnusedKickoffConnectorsInput::UnusedKickoffConnector(
            idx,
        ));
    }
    let mut outputs = vec![];
    if has_change_output(indices, datasources) {
        outputs.push(BurnUnusedKickoffConnectorsOutput::Change);
    }
    outputs.push(BurnUnusedKickoffConnectorsOutput::Anchor);

    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        inputs,
        outputs,
    )
}

impl BurnUnusedKickoffConnectorsInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let round = match tx_type {
            TransactionType::BurnUnusedKickoffConnectors(r, _) => *r,
            _ => unreachable!(
                "BurnUnused...::BurnUnusedKickoffConnectorsInput used with wrong tx_type"
            ),
        };

        match self {
            Self::UnusedKickoffConnector(idx) => InputSpec::parent(
                TransactionType::Round(round),
                RoundOutput::Kickoff(idx),
                bitcoin::Sequence::from_height(1),
            )
            .leaf(
                RoundLeaf::KickoffOneBlockTimeout,
                Actor::Operator,
                TapSighashType::Default,
            ),
        }
    }
}

impl From<BurnUnusedKickoffConnectorsInput> for Input {
    fn from(value: BurnUnusedKickoffConnectorsInput) -> Self {
        Input::BurnUnusedKickoffConnectors(value)
    }
}

impl BurnUnusedKickoffConnectorsOutput {
    pub(crate) fn materialize(
        self,
        tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let (round, indices) = match tx_type {
            TransactionType::BurnUnusedKickoffConnectors(r, i) => (*r, i),
            _ => unreachable!(
                "BurnUnused...::BurnUnusedKickoffConnectorsOutput used with wrong tx_type"
            ),
        };
        let paramset = datasources.params();

        match self {
            Self::Change => {
                let round_txhandler = cache.get_required(TransactionType::Round(round))?;

                let mut input_amount = Amount::ZERO;
                for &idx in indices {
                    let txin = round_txhandler.get_spendable_output(RoundOutput::Kickoff(idx))?;
                    input_amount = input_amount.checked_add(txin.get_prevout().value).ok_or(
                        BridgeError::ArithmeticOverflow(
                            "Amount overflow in burn unused kickoff connectors tx",
                        ),
                    )?;
                }

                if !paramset.bridge_nonstandard
                    && input_amount >= paramset.anchor_amount() + MIN_TAPROOT_AMOUNT
                {
                    Ok(UnspentTxOut::from_partial(TxOut {
                        value: input_amount - paramset.anchor_amount(),
                        script_pubkey: datasources.burn_change_address()?.script_pubkey(),
                    }))
                } else {
                    Err(TxError::Other(eyre!(
                        "burn-unused change output requested without enough input value"
                    ))
                    .into())
                }
            }
            Self::Anchor => Ok(UnspentTxOut::from_partial(anchor_output(
                paramset.anchor_amount(),
            ))),
        }
    }
}

impl From<BurnUnusedKickoffConnectorsOutput> for Output {
    fn from(value: BurnUnusedKickoffConnectorsOutput) -> Self {
        Output::BurnUnusedKickoffConnectors(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_indices_rejects_empty_input() {
        assert!(matches!(
            validate_indices(&[], 10),
            Err(BridgeError::Transaction(
                TxError::EmptyBurnUnusedKickoffConnectors
            ))
        ));
    }

    #[test]
    fn validate_indices_rejects_duplicates() {
        assert!(matches!(
            validate_indices(&[1, 1], 10),
            Err(BridgeError::Transaction(
                TxError::DuplicateBurnUnusedKickoffConnector(1)
            ))
        ));
    }

    #[test]
    fn validate_indices_rejects_out_of_range_indices() {
        assert!(matches!(
            validate_indices(&[10], 10),
            Err(BridgeError::Transaction(
                TxError::BurnUnusedKickoffConnectorIndexOutOfRange {
                    index: 10,
                    num_kickoffs: 10,
                }
            ))
        ));
    }
}
