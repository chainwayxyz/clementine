//! Emergency-stop transaction.
//!
//! This transaction moves the deposited funds into a security-council-controlled
//! output so the bridge can be halted and recovered safely.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;
use tx_builder::output::TapNodeSpec;
use tx_builder::scripts::Multisig;

use super::move_to_vault::MoveToVaultLeaf;
use super::move_to_vault::MoveToVaultOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmergencyStopInput {
    DepositInMove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmergencyStopOutput {
    EmergencyStopMain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmergencyStopLeaf {
    SecurityCouncilMultisig,
}

pub(crate) fn spec() -> TxSpec<EmergencyStopInput, EmergencyStopOutput> {
    TxSpec::new(
        bitcoin::transaction::Version::TWO,
        bitcoin::absolute::LockTime::ZERO,
        vec![EmergencyStopInput::DepositInMove],
        vec![EmergencyStopOutput::EmergencyStopMain],
    )
}

impl EmergencyStopInput {
    pub(crate) fn resolve(
        self,
        _tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            Self::DepositInMove => InputSpec::parent(
                TransactionType::MoveToVault,
                MoveToVaultOutput::DepositInMove,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                MoveToVaultLeaf::NofnSpend,
                Actor::Verifier,
                TapSighashType::SinglePlusAnyoneCanPay,
            ),
        }
    }
}

impl From<EmergencyStopInput> for Input {
    fn from(value: EmergencyStopInput) -> Self {
        Input::EmergencyStop(value)
    }
}

impl EmergencyStopOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        const EACH_EMERGENCY_STOP_VBYTES: bitcoin::Amount = bitcoin::Amount::from_sat(126);
        let deposit_data = datasources.deposit()?;
        let paramset = datasources.params();
        match self {
            Self::EmergencyStopMain => Ok(UnspentTxOut::from_taptree(
                paramset.bridge_amount - paramset.anchor_amount() - EACH_EMERGENCY_STOP_VBYTES * 3,
                None,
                vec![TapNodeSpec::leaf(
                    EmergencyStopLeaf::SecurityCouncilMultisig.into(),
                    Multisig::new(
                        deposit_data.security_council.pks.clone(),
                        deposit_data.security_council.threshold,
                    ),
                )],
            )),
        }
    }
}

impl From<EmergencyStopOutput> for Output {
    fn from(value: EmergencyStopOutput) -> Self {
        Output::EmergencyStop(value)
    }
}
