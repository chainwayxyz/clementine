//! This module contains the creation of BitVM operator assertion transactions and timeout transactions related to assertions.

use self::output::UnspentTxOut;
use super::input::UtxoVout;
use crate::builder;
pub use crate::builder::transaction::txhandler::TxHandler;
pub use crate::builder::transaction::*;
use crate::config::protocol::ProtocolParamset;
use crate::rpc::clementine::NormalSignatureKind;
use bitcoin::Sequence;
use clementine_errors::{BridgeError, TransactionType, TxError};

/// Creates a [`TxHandler`] for the `disprove_timeout_tx`.
///
/// This transaction is sent by the operator to enable sending a `reimburse_tx` later, if operator's asserted proof did not get disproved.
///
/// # Inputs
/// 1. KickoffTx: Disprove utxo
/// 2. KickoffTx: KickoffFinalizer utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
/// * `kickoff_txhandler` - The kickoff transaction handler providing the input.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A [`TxHandler`] for the disprove timeout transaction, or a [`BridgeError`] if construction fails.
pub fn create_disprove_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::DisproveTimeout)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            kickoff_txhandler.get_spendable_output(UtxoVout::Disprove)?,
            SpendPath::ScriptSpend(0),
            Sequence::from_height(paramset.disprove_timeout_timelock),
        )
        .add_input(
            NormalSignatureKind::DisproveTimeout2,
            kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(anchor_output(
            paramset.anchor_amount(),
        )))
        .finalize())
}

/// Creates a [`TxHandler`] for the `latest_blockhash_timeout_tx`.
///
/// This transaction is sent by the verifiers if the latest blockhash is not provided in time by operator.
///
/// # Inputs
/// 1. KickoffTx: LatestBlockhash utxo
/// 2. KickoffTx: KickoffFinalizer utxo
/// 3. RoundTx: BurnConnector utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
/// * `kickoff_txhandler` - The kickoff transaction handler providing the input.
/// * `round_txhandler` - The round transaction handler providing an additional input.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A [`TxHandler`] for the latest blockhash timeout transaction, or a [`BridgeError`] if construction fails.
pub fn create_latest_blockhash_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    Ok(
        TxHandlerBuilder::new(TransactionType::LatestBlockhashTimeout)
            .with_version(NON_STANDARD_V3)
            .add_input(
                NormalSignatureKind::LatestBlockhashTimeout1,
                kickoff_txhandler.get_spendable_output(UtxoVout::LatestBlockhash)?,
                SpendPath::ScriptSpend(0),
                Sequence::from_height(paramset.latest_blockhash_timeout_timelock),
            )
            .add_input(
                NormalSignatureKind::LatestBlockhashTimeout2,
                kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
                SpendPath::ScriptSpend(0),
                DEFAULT_SEQUENCE,
            )
            .add_input(
                NormalSignatureKind::LatestBlockhashTimeout3,
                round_txhandler.get_spendable_output(UtxoVout::CollateralInRound)?,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(anchor_output(
                paramset.anchor_amount(),
            )))
            .finalize(),
    )
}

/// Creates a vector of [`TxHandler`] for `mini_assert` transactions.
///
/// These transactions are used to commit BitVM assertions of operator's proof that it paid the payout corresponding to the deposit.
///
/// # Inputs
/// 1. KickoffTx: Assert utxo (per mini assert)
///
/// # Outputs
/// 1. Anchor output for CPFP
/// 2. Dummy OP_RETURN output (to pad the size of the transaction, as it is too small otherwise)
///
/// # Arguments
/// * `kickoff_txhandler` - The kickoff transaction handler providing the input.
/// * `num_asserts` - Number of mini assert transactions to create.
///
/// # Returns
/// A vector of [`TxHandler`] for mini assert transactions, or a [`BridgeError`] if construction fails.
pub fn create_mini_asserts(
    kickoff_txhandler: &TxHandler,
    num_asserts: usize,
    paramset: &'static ProtocolParamset,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..num_asserts {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::MiniAssert(idx))
                .with_version(NON_STANDARD_V3)
                .add_input(
                    NormalSignatureKind::MiniAssert1,
                    kickoff_txhandler.get_spendable_output(UtxoVout::Assert(idx))?,
                    SpendPath::ScriptSpend(1),
                    DEFAULT_SEQUENCE,
                )
                .add_output(UnspentTxOut::from_partial(
                    builder::transaction::anchor_output(paramset.anchor_amount()),
                ))
                .add_output(UnspentTxOut::from_partial(op_return_txout(b"")))
                .finalize(),
        );
    }
    Ok(txhandlers)
}

/// Creates a [`TxHandler`] for the `latest_blockhash_tx`.
///
/// This transaction is used by operator to commit the latest blockhash of the bitcoin chain. This latest blockhash will be used later
/// in the operator's bridge proof. Mainly used to reduce the time operator can spend building a private fork.
///
/// # Inputs
/// 1. KickoffTx: LatestBlockhash utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
/// 2. Dummy OP_RETURN output (to pad the size of the transaction, as it is too small otherwise)
///
/// # Arguments
/// * `kickoff_txhandler` - The kickoff transaction handler providing the input.
///
/// # Returns
/// A [`TxHandler`] for the latest blockhash transaction, or a [`BridgeError`] if construction fails.
pub fn create_latest_blockhash_txhandler(
    kickoff_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::LatestBlockhash)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::LatestBlockhash,
            kickoff_txhandler.get_spendable_output(UtxoVout::LatestBlockhash)?,
            SpendPath::ScriptSpend(1),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(anchor_output(
            paramset.anchor_amount(),
        )))
        .add_output(UnspentTxOut::from_partial(op_return_txout(b"")))
        .finalize())
}
