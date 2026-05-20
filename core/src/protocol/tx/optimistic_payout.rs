//! Optimistic-payout transaction.
//!
//! This transaction lets the signers give the deposited funds directly to the
//! withdrawing user, avoiding the full kickoff and BitVM process.

use crate::builder::transaction::{
    non_ephemeral_anchor_output, DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{ExternalInput, InputSpec, TxSpec};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::move_to_vault::MoveToVaultLeaf;
use super::move_to_vault::MoveToVaultOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptimisticPayoutInput {
    WithdrawalUtxo,
    DepositInMove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptimisticPayoutOutput {
    User,
    Anchor,
}

pub(crate) fn spec() -> TxSpec<OptimisticPayoutInput, OptimisticPayoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            OptimisticPayoutInput::WithdrawalUtxo,
            OptimisticPayoutInput::DepositInMove,
        ],
        vec![OptimisticPayoutOutput::User, OptimisticPayoutOutput::Anchor],
    )
}

impl OptimisticPayoutInput {
    pub(crate) fn resolve(
        self,
        _tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            Self::WithdrawalUtxo => {
                InputSpec::external(ExternalInput::WithdrawalUtxo, DEFAULT_SEQUENCE)
                    .key_path_with(None, TapSighashType::SinglePlusAnyoneCanPay)
            }
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
        }
    }
}

impl From<OptimisticPayoutInput> for Input {
    fn from(value: OptimisticPayoutInput) -> Self {
        Input::OptimisticPayout(value)
    }
}

impl OptimisticPayoutOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let withdrawal_data = datasources.withdrawal()?;
        match self {
            Self::User => Ok(UnspentTxOut::from_partial(
                withdrawal_data.output_txout.clone(),
            )),
            Self::Anchor => Ok(UnspentTxOut::from_partial(non_ephemeral_anchor_output())),
        }
    }
}

impl From<OptimisticPayoutOutput> for Output {
    fn from(value: OptimisticPayoutOutput) -> Self {
        Output::OptimisticPayout(value)
    }
}
