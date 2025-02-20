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

use super::txhandler::DEFAULT_SEQUENCE;
use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{TimelockScript, WinternitzCommit};
use crate::builder::transaction::creator::KickoffWinternitzKeys;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::*;
use crate::constants::{BLOCKS_PER_WEEK, KICKOFF_BLOCKHASH_COMMIT_LENGTH, MIN_TAPROOT_AMOUNT};
use crate::errors::BridgeError;
use crate::rpc::clementine::NumberedSignatureKind;
use bitcoin::Sequence;
use bitcoin::{Amount, OutPoint, TxOut, XOnlyPublicKey};
use std::sync::Arc;

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
    input_outpoint: OutPoint,
    input_amount: Amount,
    num_kickoffs_per_round: usize,
    network: bitcoin::Network,
    pubkeys: &[bitvm::signatures::winternitz::PublicKey],
) -> Result<TxHandler, BridgeError> {
    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);
    let mut builder = TxHandlerBuilder::new(TransactionType::Round).add_input(
        NormalSignatureKind::OperatorSighashDefault,
        SpendableTxIn::new(
            input_outpoint,
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

    // This 1 block is to enforce that operator has to put a sequence number in the input
    // so this spending path can't be used to send kickoff tx
    let timeout_block_count_locked_script =
        Arc::new(TimelockScript::new(Some(operator_xonly_pk), 1u16));

    builder = builder.add_output(UnspentTxOut::from_scripts(
        input_amount, // TODO: - num_kickoffs_per_sequential_collateral_tx * kickoff_sats,
        vec![],
        Some(operator_xonly_pk),
        network,
    ));

    // add kickoff utxos
    for pubkey in pubkeys.iter().take(num_kickoffs_per_round) {
        let blockhash_commit = Arc::new(WinternitzCommit::new(
            vec![(pubkey.clone(), KICKOFF_BLOCKHASH_COMMIT_LENGTH)],
            operator_xonly_pk,
        ));
        builder = builder.add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![blockhash_commit, timeout_block_count_locked_script.clone()],
            None,
            network,
        ));
    }
    // Create reimburse utxos
    for _ in 0..num_kickoffs_per_round {
        builder = builder.add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![],
            Some(operator_xonly_pk),
            network,
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
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..num_asserts {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::AssertTimeout(idx))
                .add_input(
                    (NumberedSignatureKind::AssertTimeout1, idx as i32),
                    kickoff_txhandler.get_spendable_output(5 + idx)?,
                    SpendPath::ScriptSpend(0),
                    Sequence::from_height(BLOCKS_PER_WEEK * 4),
                )
                .add_input(
                    (NumberedSignatureKind::AssertTimeout2, idx as i32),
                    kickoff_txhandler.get_spendable_output(2)?,
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
                .finalize(),
        );
    }
    Ok(txhandlers)
}

/// Creates the nth (0-indexed) `sequential_collateral_txhandler` and `reimburse_generator_txhandler` pair
/// for a sspecific operator.
pub fn create_round_nth_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    input_outpoint: OutPoint,
    input_amount: Amount,
    num_kickoffs_per_round: usize,
    network: bitcoin::Network,
    index: usize,
    pubkeys: &KickoffWinternitzKeys,
) -> Result<(TxHandler, TxHandler), BridgeError> {
    let mut round_txhandler = create_round_txhandler(
        operator_xonly_pk,
        input_outpoint,
        input_amount,
        num_kickoffs_per_round,
        network,
        pubkeys.get_keys_for_round(0),
    )?;
    let mut ready_to_reimburse_txhandler =
        create_ready_to_reimburse_txhandler(&round_txhandler, operator_xonly_pk, network)?;
    for idx in 1..index + 1 {
        round_txhandler = create_round_txhandler(
            operator_xonly_pk,
            *ready_to_reimburse_txhandler
                .get_spendable_output(0)?
                .get_prev_outpoint(),
            ready_to_reimburse_txhandler
                .get_spendable_output(0)?
                .get_prevout()
                .value,
            num_kickoffs_per_round,
            network,
            pubkeys.get_keys_for_round(idx),
        )?;
        ready_to_reimburse_txhandler =
            create_ready_to_reimburse_txhandler(&round_txhandler, operator_xonly_pk, network)?;
    }
    Ok((round_txhandler, ready_to_reimburse_txhandler))
}

pub fn create_ready_to_reimburse_txhandler(
    round_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let prevout = round_txhandler.get_spendable_output(0)?;
    Ok(TxHandlerBuilder::new(TransactionType::ReadyToReimburse)
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            prevout.clone(),
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            prevout.get_prevout().value,
            vec![],
            Some(operator_xonly_pk),
            network,
        ))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

pub fn create_unspent_kickoff_txhandlers(
    round_txhandler: &TxHandler,
    ready_to_reimburse_txhandler: &TxHandler,
    num_kickoffs_per_round: usize,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..num_kickoffs_per_round {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::UnspentKickoff(idx))
                .add_input(
                    (NumberedSignatureKind::UnspentKickoff1, idx as i32),
                    ready_to_reimburse_txhandler.get_spendable_output(0)?,
                    SpendPath::KeySpend,
                    DEFAULT_SEQUENCE,
                )
                .add_input(
                    (NumberedSignatureKind::UnspentKickoff2, idx as i32),
                    round_txhandler.get_spendable_output(1 + idx)?,
                    SpendPath::KeySpend,
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
