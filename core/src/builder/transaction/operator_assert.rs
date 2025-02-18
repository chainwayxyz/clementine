use self::input::SpendableTxIn;
use self::output::UnspentTxOut;
use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{SpendableScript, TimelockScript};
pub use crate::builder::transaction::txhandler::TxHandler;
pub use crate::builder::transaction::*;
use crate::constants::{BLOCKS_PER_WEEK, MIN_TAPROOT_AMOUNT, PARALLEL_ASSERT_TX_CHAIN_SIZE};
use crate::errors::BridgeError;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use crate::utils::SECP;
use bitcoin::hashes::Hash;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, XOnlyPublicKey};
use bitcoin::{Sequence, TapNodeHash, Txid};
use std::collections::VecDeque;
use std::sync::Arc;

/// Creates a [`TxHandler`] for the `disprove_timeout_tx`. This transaction will be sent by the operator
/// to be able to send `reimburse_tx` later.
pub fn create_disprove_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::DisproveTimeout)
        .add_input(
            NormalSignatureKind::DisproveTimeout1,
            kickoff_txhandler.get_spendable_output(4)?,
            builder::script::SpendPath::ScriptSpend(0),
            Sequence::from_height(BLOCKS_PER_WEEK * 5),
        )
        .add_input(
            NormalSignatureKind::DisproveTimeout2,
            kickoff_txhandler.get_spendable_output(2)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

pub fn create_mini_asserts(kickoff_txhandler: &TxHandler, num_asserts: usize)
    -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..num_asserts {
        txhandlers.push(TxHandlerBuilder::new(TransactionType::MiniAssert(idx))
            .add_input(
                NormalSignatureKind::MiniAssert1,
                kickoff_txhandler.get_spendable_output(5 + idx)?,
                SpendPath::ScriptSpend(1),
                DEFAULT_SEQUENCE
            ).add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
            .finalize());
    }
    Ok(txhandlers)
}