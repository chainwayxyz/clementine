//! # Collaterals
//!
//! This module contains the logic for creating the `sequential_collateral_tx`, `reimburse_generator_tx`,
//! and `kickoff_utxo_timeout_tx` transactions. These transactions are used to control the sequence of transactions
//! in the withdrawal process and limits the number of withdrawals the operator can make in a given time period.
//!
//! The flow is as follows:
//! `sequential_collateral_tx -> reimburse_generator_tx -> sequential_collateral_tx -> ...`
//!
//! The `sequential_collateral_tx` is used to create a collateral for the withdrawal. The `reimburse_generator_tx`
//! is used to reimburse the operator for the collateral. The `sequential_collateral_tx` is used to create a
//! new collateral for the withdrawal.
//!

use super::txhandler::DEFAULT_SEQUENCE;
use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::script::TimelockScript;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::*;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::errors::BridgeError;
use bitcoin::{Amount, OutPoint, TxOut, XOnlyPublicKey};
use bitcoin::{Sequence, Txid};
use std::sync::Arc;

/// Creates a [`TxHandler`] for `sequential_collateral_tx`. It will always use the first
/// output of the  previous `reimburse_generator_tx` as the input. The flow is as follows:
/// `sequential_collateral_tx -> reimburse_generator_tx -> sequential_collateral_tx -> ...`
///
/// # Returns
///
/// A `sequential_collateral_tx` that has outputs of:
///
/// 1. Operator's Burn Connector
/// 2. Operator's Time Connector: timelocked utxo for operator for the entire withdrawal time
/// 3. Kickoff input utxo(s): the utxo(s) will be used as the input(s) for the kickoff_tx(s)
/// 4. P2Anchor: Anchor output for CPFP
pub fn create_sequential_collateral_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    input_txid: Txid,
    input_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: u16,
    num_kickoffs_per_sequential_collateral_tx: usize,
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);
    let mut builder = TxHandlerBuilder::new().add_input(
        NormalSignatureKind::NotStored,
        SpendableTxIn::new(
            OutPoint {
                txid: input_txid,
                vout: 0,
            },
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
    let max_withdrawal_time_locked_script = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        max_withdrawal_time_block_count,
    ));

    let timeout_block_count_locked_script = Arc::new(TimelockScript::new(
        None,
        u16::try_from(timeout_block_count)
            .map_err(|_| BridgeError::Error("Timeout value is not u16".to_string()))?,
    ));

    builder = builder
        .add_output(UnspentTxOut::from_scripts(
            input_amount,
            vec![],
            Some(operator_xonly_pk),
            network,
        ))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![max_withdrawal_time_locked_script],
            None,
            network,
        ));

    // add kickoff utxos
    for _ in 0..num_kickoffs_per_sequential_collateral_tx {
        builder = builder.add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![timeout_block_count_locked_script.clone()],
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

/// Creates a [`TxHandler`] for `reimburse_generator_tx`. It will always use the first
/// two outputs of the  previous `sequential_collateral_tx` as the two inputs.
///
/// # Returns
///
/// A `sequential_collateral_tx` that has outputs of:
///
/// 1. Operator's Fund from the previous `sequential_collateral_tx`
/// 2. Reimburse connector utxo(s): the utxo(s) will be used as the input(s) for the reimburse_tx(s)
/// 3. P2Anchor: Anchor output for CPFP
pub fn create_reimburse_generator_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    num_kickoffs_per_sequential_collateral_tx: usize,
    max_withdrawal_time_block_count: u16,
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new()
        .add_input(
            NormalSignatureKind::NotStored,
            sequential_collateral_txhandler.get_spendable_output(0)?,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::NotStored,
            sequential_collateral_txhandler.get_spendable_output(1)?,
            SpendPath::ScriptSpend(0),
            Sequence::from_height(max_withdrawal_time_block_count),
        );

    builder = builder.add_output(UnspentTxOut::from_scripts(
        MIN_TAPROOT_AMOUNT,
        vec![],
        Some(operator_xonly_pk),
        network,
    ));

    // add reimburse utxos
    for _ in 0..num_kickoffs_per_sequential_collateral_tx {
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

/// Creates a [`TxHandler`] for the `kickoff_utxo_timeout_tx`. This transaction is sent when
/// the operator does not send the `kickoff_tx` within the timeout period (6 blocks), for a withdrawal
/// that they provided. Anyone will be able to burn the utxo after the timeout period.
pub fn create_kickoff_utxo_timeout_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
) -> Result<TxHandler, BridgeError> {
    let builder = TxHandlerBuilder::new().add_input(
        NormalSignatureKind::NotStored,
        sequential_collateral_txhandler.get_spendable_output(2 + kickoff_idx)?,
        SpendPath::ScriptSpend(1),
        DEFAULT_SEQUENCE,
    );

    // TODO: send kickoff SATs to burner address
    Ok(builder
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `kickoff_timeout_tx`. This transaction will be sent by anyone
/// in case the operator does not respond to a challenge (did not manage to send `assert_end_tx`)
/// in time, burning their burn connector.
pub fn create_kickoff_timeout_txhandler(
    kickoff_tx_handler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    let builder = TxHandlerBuilder::new()
        .add_input(
            NormalSignatureKind::KickoffTimeout1,
            kickoff_tx_handler.get_spendable_output(3)?,
            SpendPath::ScriptSpend(1),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::KickoffTimeout2,
            sequential_collateral_txhandler.get_spendable_output(0)?,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        );
    Ok(builder
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}
