//! # Collaterals
//!
//! This module contains the logic for creating the `round_tx`, `ready_to_reimburse_tx`,
//! and `unspent_kickoff_tx` transactions. These transactions are used to control the sequence of transactions
//! in the withdrawal process and limits the number of withdrawals the operator can make in a given time period.
//!
//! The flow is as follows:
//! `round_tx -> ready_to_reimburse_tx -> round_tx -> ...`
//!
//! The `round_tx` is used to create a collateral for the withdrawal, kickoff utxos for the current
//! round and the reimburse connectors for the previous round.

use super::input::get_assert_utxo_vout;
use super::txhandler::DEFAULT_SEQUENCE;
use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{TimelockScript, WinternitzCommit};
use crate::builder::transaction::creator::KickoffWinternitzKeys;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::*;
use crate::config::protocol::ProtocolParamset;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::NumberedSignatureKind;
use bitcoin::Sequence;
use bitcoin::{Amount, OutPoint, TxOut, XOnlyPublicKey};
use std::sync::Arc;

pub enum RoundTxInput {
    Prevout(SpendableTxIn),
    Collateral(OutPoint, Amount),
}

/// Creates a [`TxHandler`] for `round_tx`. It will always use the first
/// output of the  previous `ready_to_reimburse_tx` as the input. The flow is as follows:
/// `round_tx -> ready_to_reimburse_tx -> round_tx -> ...`
///
/// # Returns
///
/// A `round_tx` that has outputs of:
///
/// 1. Operator's Burn Connector
/// 2. Kickoff input utxo(s): the utxo(s) will be used as the input(s) for the kickoff_tx(s)
/// 3. Reimburse utxo(s): the utxo(s) will be used as an input to Reimburse TX
/// 4. P2Anchor: Anchor output for CPFP
pub fn create_round_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    txin: RoundTxInput,
    pubkeys: &[bitvm::signatures::winternitz::PublicKey],
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let mut builder =
        TxHandlerBuilder::new(TransactionType::Round).with_version(Version::non_standard(3));
    let input_amount;
    match txin {
        RoundTxInput::Prevout(prevout) => {
            input_amount = prevout.get_prevout().value;
            builder = builder.add_input(
                NormalSignatureKind::OperatorSighashDefault,
                prevout,
                SpendPath::KeySpend,
                Sequence::from_height(paramset.operator_reimburse_timelock),
            );
        }
        RoundTxInput::Collateral(outpoint, amount) => {
            let (op_address, op_spend) =
                create_taproot_address(&[], Some(operator_xonly_pk), paramset.network);
            input_amount = amount;
            builder = builder.add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new(
                    outpoint,
                    TxOut {
                        value: input_amount,
                        script_pubkey: op_address.script_pubkey(),
                    },
                    vec![],
                    Some(op_spend.clone()),
                ),
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            );
        }
    }

    // This 1 block is to enforce that operator has to put a sequence number in the input
    // so this spending path can't be used to send kickoff tx
    let timeout_block_count_locked_script =
        Arc::new(TimelockScript::new(Some(operator_xonly_pk), 1));

    builder = builder.add_output(UnspentTxOut::from_scripts(
        input_amount
            - (paramset.kickoff_amount + MIN_TAPROOT_AMOUNT)
                * (paramset.num_kickoffs_per_round as u64)
            - ANCHOR_AMOUNT,
        vec![],
        Some(operator_xonly_pk),
        paramset.network,
    ));

    // add kickoff utxos
    for pubkey in pubkeys.iter().take(paramset.num_kickoffs_per_round) {
        let blockhash_commit = Arc::new(WinternitzCommit::new(
            vec![(pubkey.clone(), paramset.kickoff_blockhash_commit_length)],
            operator_xonly_pk,
            paramset.winternitz_log_d,
        ));
        builder = builder.add_output(UnspentTxOut::from_scripts(
            paramset.kickoff_amount,
            vec![blockhash_commit, timeout_block_count_locked_script.clone()],
            None,
            paramset.network,
        ));
    }
    // Create reimburse utxos
    for _ in 0..paramset.num_kickoffs_per_round {
        builder = builder.add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![],
            Some(operator_xonly_pk),
            paramset.network,
        ));
    }
    Ok(builder
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `assert_timeout_tx`. This transaction will be sent by anyone
/// in case the operator did not send any of their asserts in time, burning their burn connector
/// and kickoff finalizer.
pub fn create_assert_timeout_txhandlers(
    kickoff_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
    num_asserts: usize,
    paramset: &'static ProtocolParamset,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..num_asserts {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::AssertTimeout(idx))
                .with_version(Version::non_standard(3))
                .add_input(
                    (NumberedSignatureKind::AssertTimeout1, idx as i32),
                    kickoff_txhandler.get_spendable_output(get_assert_utxo_vout(idx))?,
                    SpendPath::ScriptSpend(0),
                    Sequence::from_height(paramset.assert_timeout_timelock),
                )
                .add_input(
                    (NumberedSignatureKind::AssertTimeout2, idx as i32),
                    kickoff_txhandler.get_spendable_output(1)?,
                    SpendPath::ScriptSpend(0),
                    DEFAULT_SEQUENCE,
                )
                .add_input(
                    (NumberedSignatureKind::AssertTimeout3, idx as i32),
                    round_txhandler.get_spendable_output(0)?,
                    SpendPath::KeySpend,
                    DEFAULT_SEQUENCE,
                )
                .add_output(UnspentTxOut::from_partial(
                    builder::transaction::anchor_output(),
                ))
                .add_burn_output()
                .finalize(),
        );
    }
    Ok(txhandlers)
}

/// Creates the nth (0-indexed) `round_txhandler` and `reimburse_generator_txhandler` pair
/// for a specific operator.
pub fn create_round_nth_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    input_outpoint: OutPoint,
    input_amount: Amount,
    index: usize,
    pubkeys: &KickoffWinternitzKeys,
    paramset: &'static ProtocolParamset,
) -> Result<(TxHandler, TxHandler), BridgeError> {
    let mut round_txhandler = create_round_txhandler(
        operator_xonly_pk,
        RoundTxInput::Collateral(input_outpoint, input_amount),
        pubkeys.get_keys_for_round(0),
        paramset,
    )?;
    let mut ready_to_reimburse_txhandler =
        create_ready_to_reimburse_txhandler(&round_txhandler, operator_xonly_pk, paramset)?;
    for idx in 1..=index {
        round_txhandler = create_round_txhandler(
            operator_xonly_pk,
            RoundTxInput::Prevout(ready_to_reimburse_txhandler.get_spendable_output(0)?),
            pubkeys.get_keys_for_round(idx),
            paramset,
        )?;
        ready_to_reimburse_txhandler =
            create_ready_to_reimburse_txhandler(&round_txhandler, operator_xonly_pk, paramset)?;
    }
    Ok((round_txhandler, ready_to_reimburse_txhandler))
}

pub fn create_ready_to_reimburse_txhandler(
    round_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let prevout = round_txhandler.get_spendable_output(0)?;
    let prev_value = prevout.get_prevout().value;

    Ok(TxHandlerBuilder::new(TransactionType::ReadyToReimburse)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            prevout,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            prev_value - ANCHOR_AMOUNT,
            vec![],
            Some(operator_xonly_pk),
            paramset.network,
        ))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

pub fn create_unspent_kickoff_txhandlers(
    round_txhandler: &TxHandler,
    ready_to_reimburse_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..paramset.num_kickoffs_per_round {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::UnspentKickoff(idx))
                .with_version(Version::non_standard(3))
                .add_input(
                    (NumberedSignatureKind::UnspentKickoff1, idx as i32),
                    ready_to_reimburse_txhandler.get_spendable_output(0)?,
                    SpendPath::KeySpend,
                    DEFAULT_SEQUENCE,
                )
                .add_input(
                    (NumberedSignatureKind::UnspentKickoff2, idx as i32),
                    round_txhandler.get_spendable_output(1 + idx)?,
                    SpendPath::ScriptSpend(1),
                    DEFAULT_SEQUENCE,
                )
                .add_output(UnspentTxOut::from_partial(
                    builder::transaction::anchor_output(),
                ))
                .finalize(),
        );
    }
    Ok(txhandlers)
}

pub fn create_burn_unused_kickoff_connectors_txhandler(
    round_txhandler: &TxHandler,
    unused_kickoff_connectors_indices: &[usize], // indices of the kickoff connectors that are not used, 0 indexed, 0 => first kickoff connector
    change_address: &Address,
) -> Result<TxHandler, BridgeError> {
    let mut tx_handler_builder =
        TxHandlerBuilder::new(TransactionType::BurnUnusedKickoffConnectors)
            .with_version(Version::non_standard(3));
    for idx in unused_kickoff_connectors_indices {
        tx_handler_builder = tx_handler_builder.add_input(
            NormalSignatureKind::OperatorSighashDefault,
            round_txhandler.get_spendable_output(1 + idx)?,
            SpendPath::ScriptSpend(1),
            Sequence::from_height(1),
        );
    }
    tx_handler_builder = tx_handler_builder.add_output(UnspentTxOut::from_partial(TxOut {
        value: MIN_TAPROOT_AMOUNT,
        script_pubkey: change_address.script_pubkey(),
    }));
    tx_handler_builder = tx_handler_builder.add_output(UnspentTxOut::from_partial(
        builder::transaction::anchor_output(),
    ));
    Ok(tx_handler_builder.finalize())
}
