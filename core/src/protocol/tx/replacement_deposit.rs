//! Replacement-deposit transaction.
//!
//! This transaction replaces the original deposit output with a new deposit path
//! while preserving the bridge amount and creating a zero-sat anchor.

use crate::builder::transaction::{
    anchor_output, DataSources, SpendableTxIn, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::deposit::{DepositSpendTree, DepositTreeLeaf};
use crate::protocol::ids::{Actor, Input, Leaf, Output, TransactionType};
use crate::protocol::spec::{ExternalInput, InputSpec, TxSpec};
use bitcoin::{Amount, TapSighashType};
use clementine_errors::BridgeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplacementDepositInput {
    ReplacementOutpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplacementDepositOutput {
    Main,
    Anchor,
}

pub(crate) fn spec() -> TxSpec<ReplacementDepositInput, ReplacementDepositOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![ReplacementDepositInput::ReplacementOutpoint],
        vec![
            ReplacementDepositOutput::Main,
            ReplacementDepositOutput::Anchor,
        ],
    )
}

impl ReplacementDepositInput {
    pub(crate) fn resolve(
        self,
        _tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            Self::ReplacementOutpoint => {
                InputSpec::external(ExternalInput::DepositOutpoint, DEFAULT_SEQUENCE).leaf(
                    DepositTreeLeaf::DepositScript,
                    Actor::SecurityCouncil,
                    TapSighashType::SinglePlusAnyoneCanPay,
                )
            }
        }
    }
}

impl From<ReplacementDepositInput> for Input {
    fn from(value: ReplacementDepositInput) -> Self {
        Input::ReplacementDeposit(value)
    }
}

impl ReplacementDepositOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let nofn_xonly_pk = datasources.deposit_mut()?.get_nofn_xonly_pk()?;
        let replacement_data = datasources.replacement_deposit()?.clone();
        let paramset = datasources.params();
        match self {
            Self::Main => {
                let output = DepositSpendTree::from_replacement_deposit(
                    nofn_xonly_pk,
                    replacement_data.old_move_txid,
                    replacement_data.security_council,
                )
                .unspent_txout(paramset.bridge_amount, paramset.network)?;
                Ok(UnspentTxOut::new(
                    output.txout().clone(),
                    output.scripts().clone(),
                    output
                        .named_leaves()
                        .iter()
                        .cloned()
                        .map(|(leaf, script)| (Leaf::External(leaf), script))
                        .collect(),
                    output.spendinfo().clone(),
                ))
            }
            Self::Anchor => Ok(UnspentTxOut::from_partial(anchor_output(Amount::from_sat(
                0,
            )))),
        }
    }
}

impl From<ReplacementDepositOutput> for Output {
    fn from(value: ReplacementDepositOutput) -> Self {
        Output::ReplacementDeposit(value)
    }
}

pub(crate) fn materialize_replacement_input(
    datasources: &mut impl DataSources,
) -> Result<SpendableTxIn, BridgeError> {
    let replacement_data = datasources.replacement_deposit()?.clone();
    let paramset = datasources.params();
    let tree = DepositSpendTree::from_move_to_vault_output(
        replacement_data.old_nofn_xonly_pk,
        replacement_data.security_council.clone(),
    );
    let deposit_output = tree.unspent_txout(paramset.bridge_amount, paramset.network)?;
    let output = UnspentTxOut::new(
        deposit_output.txout().clone(),
        deposit_output.scripts().clone(),
        deposit_output
            .named_leaves()
            .iter()
            .cloned()
            .map(|(leaf, script)| (Leaf::External(leaf), script))
            .collect(),
        deposit_output.spendinfo().clone(),
    );

    Ok(SpendableTxIn::from_output(
        replacement_data.input_outpoint,
        &output,
    ))
}
