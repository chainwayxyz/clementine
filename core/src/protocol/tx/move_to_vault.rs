//! Move-to-vault transaction.
//!
//! This transaction moves the deposited funds into the bridge-controlled vault
//! output and creates the initial anchor output.

use crate::builder::transaction::{
    anchor_output, DataSources, SpendableTxIn, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::deposit::{DepositSpendTree, DepositTreeLeaf};
use crate::protocol::ids::{Actor, Input, Leaf, Output, TransactionType};
use crate::protocol::spec::{ExternalInput, InputSpec, TxSpec};
use bitcoin::{Amount, TapSighashType};
use clementine_errors::{BridgeError, TxError};
use eyre::eyre;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoveToVaultInput {
    DepositOutpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoveToVaultOutput {
    DepositInMove,
    Anchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoveToVaultLeaf {
    NofnSpend,
    SecurityCouncilMultisig,
}

pub(crate) fn spec() -> TxSpec<MoveToVaultInput, MoveToVaultOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![MoveToVaultInput::DepositOutpoint],
        vec![MoveToVaultOutput::DepositInMove, MoveToVaultOutput::Anchor],
    )
}

impl MoveToVaultInput {
    pub(crate) fn resolve(
        self,
        _tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            Self::DepositOutpoint => {
                InputSpec::external(ExternalInput::DepositOutpoint, DEFAULT_SEQUENCE).leaf(
                    DepositTreeLeaf::DepositScript,
                    Actor::Verifier,
                    TapSighashType::Default,
                )
            }
        }
    }
}

impl From<MoveToVaultInput> for Input {
    fn from(value: MoveToVaultInput) -> Self {
        Input::MoveToVault(value)
    }
}

impl MoveToVaultOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let paramset = datasources.params();
        let deposit_data = datasources.deposit_mut()?;
        match self {
            Self::DepositInMove => {
                let tree = DepositSpendTree::from_move_to_vault_output(
                    deposit_data.get_nofn_xonly_pk()?,
                    deposit_data.security_council.clone(),
                );
                let output = tree.unspent_txout(paramset.bridge_amount, paramset.network)?;
                Ok(UnspentTxOut::new(
                    output.txout().clone(),
                    output.scripts().clone(),
                    vec![
                        (
                            MoveToVaultLeaf::NofnSpend.into(),
                            tree.leaf_script(DepositTreeLeaf::DepositScript)
                                .cloned()
                                .ok_or_else(|| {
                                    TxError::Other(eyre!("move-to-vault tree missing deposit leaf"))
                                })?,
                        ),
                        (
                            MoveToVaultLeaf::SecurityCouncilMultisig.into(),
                            tree.leaf_script(DepositTreeLeaf::SecurityCouncilMultisig)
                                .cloned()
                                .ok_or_else(|| {
                                    TxError::Other(eyre!(
                                        "move-to-vault tree missing security council leaf"
                                    ))
                                })?,
                        ),
                    ],
                    output.spendinfo().clone(),
                ))
            }
            Self::Anchor => Ok(UnspentTxOut::from_partial(anchor_output(Amount::from_sat(
                0,
            )))),
        }
    }
}

impl From<MoveToVaultOutput> for Output {
    fn from(value: MoveToVaultOutput) -> Self {
        Output::MoveToVault(value)
    }
}

pub(crate) fn materialize_deposit_input(
    datasources: &mut impl DataSources,
) -> Result<SpendableTxIn, BridgeError> {
    let paramset = datasources.params();
    let deposit_data = datasources.deposit_mut()?;
    let tree = deposit_data.spend_tree(paramset)?;
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
        deposit_data.get_deposit_outpoint(),
        &output,
    ))
}
