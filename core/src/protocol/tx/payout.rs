//! Payout transaction.
//!
//! This transaction fronts the user withdrawal on Bitcoin. The operator later
//! follows up with kickoff to get reimbursed.

use crate::builder::transaction::{
    anchor_output, op_return_txout, DataSources, SpendableTxIn, TxCache, UnspentTxOut,
};
use crate::constants::{NON_EPHEMERAL_ANCHOR_AMOUNT, NON_STANDARD_V3};
use crate::protocol::ids::{Input, Output, TransactionType};
use crate::protocol::spec::{ExternalInput, InputSpec, TxSpec};
use bitcoin::script::PushBytesBuf;
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayoutInput {
    WithdrawalUtxo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayoutOutput {
    User,
    Anchor,
    OperatorMarker,
}

pub(crate) fn spec() -> TxSpec<PayoutInput, PayoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![PayoutInput::WithdrawalUtxo],
        vec![
            PayoutOutput::User,
            PayoutOutput::Anchor,
            PayoutOutput::OperatorMarker,
        ],
    )
}

impl PayoutInput {
    pub(crate) fn resolve(
        self,
        _tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            Self::WithdrawalUtxo => InputSpec::external(
                ExternalInput::WithdrawalUtxo,
                crate::builder::transaction::DEFAULT_SEQUENCE,
            )
            .key_path_with(None, TapSighashType::SinglePlusAnyoneCanPay),
        }
    }
}

impl From<PayoutInput> for Input {
    fn from(value: PayoutInput) -> Self {
        Input::Payout(value)
    }
}

impl PayoutOutput {
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
            Self::Anchor => Ok(UnspentTxOut::from_partial(anchor_output(
                NON_EPHEMERAL_ANCHOR_AMOUNT,
            ))),
            Self::OperatorMarker => {
                let push_bytes = PushBytesBuf::from(withdrawal_data.operator_xonly_pk.serialize());
                Ok(UnspentTxOut::from_partial(op_return_txout(push_bytes)))
            }
        }
    }
}

impl From<PayoutOutput> for Output {
    fn from(value: PayoutOutput) -> Self {
        Output::Payout(value)
    }
}

pub(crate) fn materialize_withdrawal_input(
    datasources: &mut impl DataSources,
) -> Result<SpendableTxIn, BridgeError> {
    let withdrawal_data = datasources.withdrawal()?;
    Ok(SpendableTxIn::new_partial(
        withdrawal_data.input_utxo.outpoint,
        withdrawal_data.input_utxo.txout.clone(),
    ))
}
