//! Round transaction family.
//!
//! Round transactions control the long-lived collateral chain of the protocol.
//! A round creates the next collateral output, kickoff outputs for the current
//! round, reimbursement connectors, and an anchor.

use crate::builder::address::create_taproot_address;
use crate::builder::transaction::{
    anchor_output, DataSources, SpendableTxIn, TxCache, TxCacheExt, UnspentTxOut,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, RoundIdx, TransactionType};
use crate::protocol::spec::{ExternalInput, InputSpec, TxSpec};
use bitcoin::{TapSighashType, TxOut};
use clementine_errors::BridgeError;
use clementine_primitives::BridgeRound;
use std::sync::Arc;
use tx_builder::output::TapNodeSpec;
use tx_builder::scripts::{TimelockScript, WinternitzCommit};

use super::ready_to_reimburse::{ReadyToReimburseInput, ReadyToReimburseOutput};

pub(crate) fn external_collateral_input(
    datasources: &mut impl DataSources,
) -> Result<SpendableTxIn, BridgeError> {
    let operator_data = datasources.operator()?;
    let paramset = datasources.params();
    let (op_address, op_spend) =
        create_taproot_address(&[], Some(operator_data.xonly_pk), paramset.network);
    Ok(SpendableTxIn::new(
        operator_data.collateral_funding_outpoint,
        TxOut {
            value: paramset.collateral_funding_amount,
            script_pubkey: op_address.script_pubkey(),
        },
        vec![],
        vec![],
        Some(Arc::new(op_spend)),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundInput {
    // Round 0: Collateral funding, Round > 0: ReadyToReimburse
    Collateral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundOutput {
    RemainingCollateral,
    Kickoff(usize),
    UnspentKickoff(usize, usize),
    Anchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundLeaf {
    BlockhashCommit,
    KickoffOneBlockTimeout,
}

pub(crate) fn spec(num_kickoffs: usize) -> TxSpec<RoundInput, RoundOutput> {
    let mut outputs = vec![RoundOutput::RemainingCollateral];
    for i in 0..num_kickoffs {
        outputs.push(RoundOutput::Kickoff(i));
    }
    for i in 0..num_kickoffs {
        outputs.push(RoundOutput::UnspentKickoff(i, num_kickoffs));
    }
    outputs.push(RoundOutput::Anchor);

    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![RoundInput::Collateral],
        outputs,
    )
}

impl RoundInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let round = match tx_type {
            TransactionType::Round(r) => *r,
            _ => unreachable!("round::RoundInput used with wrong tx_type"),
        };

        match self {
            Self::Collateral => {
                if round.0 == 0 {
                    InputSpec::external(
                        ExternalInput::OperatorCollateral,
                        crate::builder::transaction::DEFAULT_SEQUENCE,
                    )
                    .key_path(Actor::Operator, TapSighashType::Default)
                } else {
                    let prev_round = RoundIdx::new(round.0 - 1);
                    InputSpec::parent(
                        TransactionType::ReadyToReimburse(prev_round),
                        ReadyToReimburseOutput::Collateral,
                        bitcoin::Sequence::from_height(
                            datasources.params().operator_reimburse_timelock,
                        ),
                    )
                    .key_path(Actor::Operator, TapSighashType::Default)
                }
            }
        }
    }
}

impl From<RoundInput> for Input {
    fn from(value: RoundInput) -> Self {
        match value {
            RoundInput::Collateral => ReadyToReimburseInput::CollateralInRound.into(),
        }
    }
}

impl RoundOutput {
    pub(crate) fn materialize(
        self,
        tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let round = match tx_type {
            TransactionType::Round(r) => *r,
            _ => unreachable!("round::RoundOutput used with wrong tx_type"),
        };
        let paramset = datasources.params();
        let operator_data = datasources.operator()?;

        match self {
            Self::RemainingCollateral => {
                let input_amount = if round.0 == 0 {
                    paramset.collateral_funding_amount
                } else {
                    let prev_round = RoundIdx::new(round.0 - 1);
                    let prev_ready =
                        cache.get_required(TransactionType::ReadyToReimburse(prev_round))?;
                    let prevout =
                        prev_ready.get_spendable_output(ReadyToReimburseOutput::Collateral)?;
                    prevout.get_prevout().value
                };

                let total_required = (paramset.kickoff_amount + paramset.default_utxo_amount())
                    .checked_mul(paramset.num_kickoffs_per_round as u64)
                    .and_then(|kickoff_total| kickoff_total.checked_add(paramset.anchor_amount()))
                    .ok_or(BridgeError::ArithmeticOverflow(
                        "Total required amount calculation overflow",
                    ))?;
                let remaining_amount = input_amount.checked_sub(total_required).ok_or(
                    BridgeError::InsufficientFunds(
                        "Input amount insufficient for required outputs",
                    ),
                )?;

                Ok(UnspentTxOut::key_path(
                    remaining_amount,
                    Some(operator_data.xonly_pk),
                ))
            }
            Self::Kickoff(idx) => {
                let kickoff_keys = datasources.kickoff_keys()?;
                let round_idx = BridgeRound::Round(round.0);
                let pubkeys = kickoff_keys.get_keys_for_round(round_idx)?;
                let pubkey = &pubkeys[idx];
                let timeout_script = TimelockScript::new(Some(operator_data.xonly_pk), 1);
                let blockhash_commit = WinternitzCommit::new(
                    vec![(pubkey.clone(), paramset.kickoff_blockhash_commit_length)],
                    operator_data.xonly_pk,
                    paramset.winternitz_log_d,
                );
                Ok(UnspentTxOut::from_taptree(
                    paramset.kickoff_amount,
                    None,
                    vec![
                        TapNodeSpec::leaf(RoundLeaf::BlockhashCommit.into(), blockhash_commit),
                        TapNodeSpec::leaf(RoundLeaf::KickoffOneBlockTimeout.into(), timeout_script),
                    ],
                ))
            }
            Self::UnspentKickoff(_, _) => Ok(UnspentTxOut::key_path(
                paramset.default_utxo_amount(),
                Some(operator_data.xonly_pk),
            )),
            Self::Anchor => Ok(UnspentTxOut::from_partial(anchor_output(
                paramset.anchor_amount(),
            ))),
        }
    }
}

impl From<RoundOutput> for Output {
    fn from(value: RoundOutput) -> Self {
        Output::Round(value)
    }
}
