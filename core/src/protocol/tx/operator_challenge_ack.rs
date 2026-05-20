//! Operator-challenge-ack transaction.
//!
//! This transaction is used by the operator to acknowledge a watchtower
//! challenge and reveal the required preimage.

use crate::builder::transaction::{
    op_return_txout, DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_watchtower_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorChallengeAckInput {
    WatchtowerChallengeAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorChallengeAckOutput {
    Anchor,
    Padding,
}

pub(crate) fn spec() -> TxSpec<OperatorChallengeAckInput, OperatorChallengeAckOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![OperatorChallengeAckInput::WatchtowerChallengeAck],
        vec![
            OperatorChallengeAckOutput::Anchor,
            OperatorChallengeAckOutput::Padding,
        ],
    )
}

impl OperatorChallengeAckInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff, watchtower_idx) = round_kickoff_watchtower_from(tx_type);
        match self {
            Self::WatchtowerChallengeAck => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::WatchtowerChallengeAck(watchtower_idx),
                DEFAULT_SEQUENCE,
            )
            .leaf(
                KickoffLeaf::WatchtowerChallengeAck(watchtower_idx),
                Actor::Operator,
                TapSighashType::Default,
            ),
        }
    }
}

impl From<OperatorChallengeAckInput> for Input {
    fn from(value: OperatorChallengeAckInput) -> Self {
        Input::OperatorChallengeAck(value)
    }
}

impl OperatorChallengeAckOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            Self::Anchor => Ok(anchor_output_utxo(datasources)),
            Self::Padding => Ok(UnspentTxOut::from_partial(op_return_txout(b"PADDING"))),
        }
    }
}

impl From<OperatorChallengeAckOutput> for Output {
    fn from(value: OperatorChallengeAckOutput) -> Self {
        Output::OperatorChallengeAck(value)
    }
}
