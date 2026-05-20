//! Latest-blockhash-timeout transaction.
//!
//! This transaction is sent if the latest blockhash is not provided in time by
//! the operator.

use crate::builder::transaction::{DataSources, TxCache, UnspentTxOut, DEFAULT_SEQUENCE};
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::{Actor, Input, Output, TransactionType};
use crate::protocol::spec::{InputSpec, TxSpec};
use crate::protocol::tx::common::{anchor_output_utxo, round_kickoff_from};
use bitcoin::TapSighashType;
use clementine_errors::BridgeError;

use super::kickoff::{KickoffLeaf, KickoffOutput};
use super::round::RoundOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LatestBlockhashTimeoutInput {
    LatestBlockhash,
    KickoffFinalizer,
    CollateralInRound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LatestBlockhashTimeoutOutput {
    Anchor,
}

pub(crate) fn spec() -> TxSpec<LatestBlockhashTimeoutInput, LatestBlockhashTimeoutOutput> {
    TxSpec::new(
        NON_STANDARD_V3,
        bitcoin::absolute::LockTime::ZERO,
        vec![
            LatestBlockhashTimeoutInput::LatestBlockhash,
            LatestBlockhashTimeoutInput::KickoffFinalizer,
            LatestBlockhashTimeoutInput::CollateralInRound,
        ],
        vec![LatestBlockhashTimeoutOutput::Anchor],
    )
}

impl LatestBlockhashTimeoutInput {
    pub(crate) fn resolve(
        self,
        tx_type: &TransactionType,
        datasources: &impl DataSources,
    ) -> InputSpec {
        let (round, kickoff) = round_kickoff_from(tx_type);
        match self {
            Self::LatestBlockhash => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::LatestBlockhash,
                bitcoin::Sequence::from_height(
                    datasources.params().latest_blockhash_timeout_timelock,
                ),
            )
            .leaf(
                KickoffLeaf::LatestBlockhashTimeout,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::KickoffFinalizer => InputSpec::parent(
                TransactionType::Kickoff(round, kickoff),
                KickoffOutput::Finalizer,
                DEFAULT_SEQUENCE,
            )
            .leaf(
                KickoffLeaf::NofnSpend,
                Actor::Verifier,
                TapSighashType::Default,
            ),
            Self::CollateralInRound => InputSpec::parent(
                TransactionType::Round(round),
                RoundOutput::RemainingCollateral,
                DEFAULT_SEQUENCE,
            )
            .key_path(Actor::Operator, TapSighashType::Default),
        }
    }
}

impl From<LatestBlockhashTimeoutInput> for Input {
    fn from(value: LatestBlockhashTimeoutInput) -> Self {
        Input::LatestBlockhashTimeout(value)
    }
}

impl LatestBlockhashTimeoutOutput {
    pub(crate) fn materialize(
        self,
        _tx_type: &TransactionType,
        datasources: &mut impl DataSources,
        _cache: &TxCache,
    ) -> Result<UnspentTxOut, BridgeError> {
        match self {
            Self::Anchor => Ok(anchor_output_utxo(datasources)),
        }
    }
}

impl From<LatestBlockhashTimeoutOutput> for Output {
    fn from(value: LatestBlockhashTimeoutOutput) -> Self {
        Output::LatestBlockhashTimeout(value)
    }
}
