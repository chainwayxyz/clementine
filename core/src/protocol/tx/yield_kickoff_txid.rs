use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut};
use crate::protocol::ids::{Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use clementine_errors::BridgeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YieldKickoffTxidInput {
    Marker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YieldKickoffTxidOutput {}

/// Placeholder spec for `YieldKickoffTxid`.
///
/// This tx type is currently a signaling item in sighash flows, not a real
/// on-chain transaction family. Keeping a dummy spec here allows typed dispatch
/// to remain exhaustive during migration.
pub(crate) fn spec() -> TxSpec<YieldKickoffTxidInput, YieldKickoffTxidOutput> {
    TxSpec::new(
        bitcoin::transaction::Version::TWO,
        bitcoin::absolute::LockTime::ZERO,
        vec![],
        vec![],
    )
}

impl YieldKickoffTxidInput {
    pub(crate) fn resolve(
        self,
        _tx_type: &TransactionType,
        _datasources: &impl DataSources,
    ) -> InputSpec {
        match self {
            // YieldKickoffTxid has no on-chain inputs; this id exists for sighash signaling.
            Self::Marker => {
                unreachable!("yield_kickoff_txid::YieldKickoffTxidInput::Marker has no InputSpec")
            }
        }
    }
}

impl YieldKickoffTxidOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        _datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {}
    }
}

impl From<YieldKickoffTxidInput> for Input {
    fn from(value: YieldKickoffTxidInput) -> Self {
        Input::YieldKickoffTxid(value)
    }
}

impl From<YieldKickoffTxidOutput> for Output {
    fn from(value: YieldKickoffTxidOutput) -> Self {
        match value {}
    }
}
