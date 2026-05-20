//! Latest-blockhash transaction.
//!
//! This transaction commits the latest Bitcoin blockhash for the operator's
//! bridge proof, helping reduce the operator's ability to build a private fork.

use crate::builder::transaction::{
    op_return_txout, DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE,
};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LatestBlockhashInput {
    LatestBlockhash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LatestBlockhashOutput {
    Anchor,
    Padding,
}

pub(crate) fn spec() -> TxSpec<LatestBlockhashInput, LatestBlockhashOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![LatestBlockhashInput::LatestBlockhash],
        vec![
            LatestBlockhashOutput::Anchor,
            LatestBlockhashOutput::Padding,
        ],
    )
}

impl LatestBlockhashInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            Self::LatestBlockhash => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::LatestBlockhash,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                KickoffLeaf::LatestBlockhash,
                Actor::Operator,
                TapSighashType::Default,
            ),
        }
    }
}

impl From<LatestBlockhashInput> for Input {
    fn from(value: LatestBlockhashInput) -> Self {
        Input::LatestBlockhash(value)
    }
}

impl LatestBlockhashOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            Self::Anchor => Ok(anchor_output_utxo(datasources)),
            Self::Padding => Ok(UnspentTxOut::from_partial(op_return_txout(b""))),
        }
    }
}

impl From<LatestBlockhashOutput> for Output {
    fn from(value: LatestBlockhashOutput) -> Self {
        Output::LatestBlockhash(value)
    }
}
