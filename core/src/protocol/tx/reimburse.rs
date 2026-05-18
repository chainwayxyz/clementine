//! Reimburse transaction.
//!
//! This transaction reimburses the operator after it fronted a user payout and
//! no successful challenge or disprove blocked reimbursement.

use crate::builder::transaction::{
    DataSources, TxCache, TxCacheExt, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, RoundIdx, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::TapSighashType;
use bitcoin::TxOut;
use clementine_errors::BridgeError;

use super::kickoff::KickoffLeaf;
use super::move_to_vault::MoveToVaultLeaf;
use super::{kickoff::KickoffOutput, move_to_vault::MoveToVaultOutput, round::RoundOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReimburseInput {
    DepositInMove,
    ReimburseInKickoff,
    ReimburseInRound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReimburseOutput {
    OperatorReimbursement,
    Anchor,
}

pub(crate) fn spec() -> TxSpec<ReimburseInput, ReimburseOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            ReimburseInput::DepositInMove,
            ReimburseInput::ReimburseInKickoff,
            ReimburseInput::ReimburseInRound,
        ],
        vec![
            ReimburseOutput::OperatorReimbursement,
            ReimburseOutput::Anchor,
        ],
    )
}

impl ReimburseInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        let paramset = datasources.params();
        let next_round = RoundIdx::new(round.0 + 1);
        match self {
            Self::DepositInMove => InputSpec::parent(
                TransactionType::MoveToVault,
                MoveToVaultOutput::DepositInMove,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                MoveToVaultLeaf::NofnSpend,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::ReimburseInKickoff => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Reimburse,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                KickoffLeaf::NofnSpend,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::ReimburseInRound => InputSpec::parent(
                TransactionType::Round(next_round),
                RoundOutput::UnspentKickoff(kickoff.0, paramset.num_kickoffs_per_round),
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Operator, TapSighashType::Default),
        }
    }
}

impl From<ReimburseInput> for Input {
    fn from(value: ReimburseInput) -> Self {
        Input::Reimburse(value)
    }
}

impl ReimburseOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            ReimburseOutput::OperatorReimbursement => {
                let move_to_vault = cache.get_required(TransactionType::MoveToVault)?;
                let deposit_in_move =
                    move_to_vault.get_spendable_output(MoveToVaultOutput::DepositInMove)?;
                Ok(UnspentTxOut::from_partial(TxOut {
                    value: deposit_in_move.get_prevout().value,
                    script_pubkey: datasources.operator()?.reimburse_addr.script_pubkey(),
                }))
            }
            ReimburseOutput::Anchor => Ok(anchor_output_utxo(datasources)),
        }
    }
}

impl From<ReimburseOutput> for Output {
    fn from(value: ReimburseOutput) -> Self {
        Output::Reimburse(value)
    }
}
