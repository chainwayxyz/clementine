//! Challenge transaction.
//!
//! This transaction records a successful operator challenge and pays the
//! operator reimbursement amount, with an optional challenger marker.

use crate::builder::transaction::{
    op_return_txout, DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::round_kickoff_from;
use bitcoin::TapSighashType;
use bitcoin::TxOut;
use clementine_errors::{BridgeError, TxError};
use eyre::eyre;

use super::kickoff::{KickoffLeaf, KickoffOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeInput {
    Challenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeOutput {
    OperatorReimbursement,
    ChallengerMarker,
}

pub(crate) fn spec(datasources: &impl DataSources) -> TxSpec<ChallengeInput, ChallengeOutput> {
    let mut outputs = vec![ChallengeOutput::OperatorReimbursement];
    if datasources
        .challenger_evm_address()
        .map(|address| address.is_some())
        .unwrap_or(false)
    {
        outputs.push(ChallengeOutput::ChallengerMarker);
    }

    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![ChallengeInput::Challenge],
        outputs,
    )
}

impl ChallengeInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            ChallengeInput::Challenge => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Challenge,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                KickoffLeaf::OperatorImmediate,
                Actor::Operator,
                TapSighashType::SinglePlusAnyoneCanPay,
            ),
        }
    }
}

impl From<ChallengeInput> for Input {
    fn from(value: ChallengeInput) -> Self {
        Input::Challenge(value)
    }
}

impl ChallengeOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        let paramset = datasources.params();

        match self {
            ChallengeOutput::OperatorReimbursement => Ok(UnspentTxOut::from_partial(TxOut {
                value: paramset.operator_challenge_amount,
                script_pubkey: datasources.operator()?.reimburse_addr.script_pubkey(),
            })),
            ChallengeOutput::ChallengerMarker => {
                let evm = datasources.challenger_evm_address()?.ok_or_else(|| {
                    TxError::Other(eyre!(
                        "challenger marker output requested without challenger data"
                    ))
                })?;
                Ok(UnspentTxOut::from_partial(op_return_txout(evm.0)))
            }
        }
    }
}

impl From<ChallengeOutput> for Output {
    fn from(value: ChallengeOutput) -> Self {
        Output::Challenge(value)
    }
}
