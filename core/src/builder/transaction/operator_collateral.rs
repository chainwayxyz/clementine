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

use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::*;
use crate::constants::MIN_TAPROOT_AMOUNT;
use bitcoin::{Amount, OutPoint, TxOut, XOnlyPublicKey};
use bitcoin::{Network, Txid};

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
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: input_txid,
            vout: 0,
        }]
        .into(),
    );
    let max_withdrawal_time_locked_script =
        builder::script::generate_checksig_relative_timelock_script(
            operator_xonly_pk,
            max_withdrawal_time_block_count,
        );

    let timeout_block_count_locked_script =
        builder::script::generate_relative_timelock_script(timeout_block_count);

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);
    let (reimburse_gen_connector, reimburse_gen_spend) =
        create_taproot_address(&[max_withdrawal_time_locked_script.clone()], None, network);
    let (kickoff_utxo, kickoff_utxo_spend) = create_taproot_address(
        &[timeout_block_count_locked_script.clone()],
        Some(operator_xonly_pk),
        network,
    );

    let kickoff_txout = TxOut {
        value: MIN_TAPROOT_AMOUNT,
        script_pubkey: kickoff_utxo.script_pubkey(),
    };

    let mut out_scripts = vec![vec![], vec![max_withdrawal_time_locked_script]];

    let mut out_taproot_spend_infos = vec![Some(op_spend.clone()), Some(reimburse_gen_spend)];

    let mut tx_outs = vec![
        TxOut {
            value: input_amount,
            script_pubkey: op_address.script_pubkey(),
        },
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: reimburse_gen_connector.script_pubkey(),
        },
    ];

    // add kickoff utxos
    for _ in 0..num_kickoffs_per_sequential_collateral_tx {
        tx_outs.push(kickoff_txout.clone());
        out_scripts.push(vec![timeout_block_count_locked_script.clone()]);
        out_taproot_spend_infos.push(Some(kickoff_utxo_spend.clone()));
    }

    // add anchor
    tx_outs.push(builder::script::anchor_output());
    out_scripts.push(vec![]);
    out_taproot_spend_infos.push(None);

    let sequential_collateral_tx1 = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: sequential_collateral_tx1.compute_txid(),
        tx: sequential_collateral_tx1,
        prevouts: vec![TxOut {
            script_pubkey: op_address.script_pubkey(),
            value: input_amount,
        }],
        prev_taproot_spend_infos: vec![Some(op_spend.clone())],
        prev_scripts: vec![vec![]],
        out_scripts,
        out_taproot_spend_infos,
    }
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
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            (
                OutPoint {
                    txid: sequential_collateral_txhandler.txid,
                    vout: 0,
                },
                None,
            ),
            (
                OutPoint {
                    txid: sequential_collateral_txhandler.txid,
                    vout: 1,
                },
                Some(max_withdrawal_time_block_count),
            ),
        ]
        .into(),
    );

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    let reimburse_txout = TxOut {
        value: MIN_TAPROOT_AMOUNT,
        script_pubkey: op_address.script_pubkey(),
    };

    let mut out_scripts = vec![vec![]];

    let mut out_taproot_spend_infos = vec![Some(op_spend.clone())];

    let mut tx_outs = vec![TxOut {
        value: sequential_collateral_txhandler.tx.output[0].value,
        script_pubkey: op_address.script_pubkey(),
    }];

    // add reimburse utxos
    for _ in 0..num_kickoffs_per_sequential_collateral_tx {
        tx_outs.push(reimburse_txout.clone());
        out_scripts.push(vec![]);
        out_taproot_spend_infos.push(Some(op_spend.clone()));
    }
    // add anchor
    tx_outs.push(builder::script::anchor_output());
    out_scripts.push(vec![]);
    out_taproot_spend_infos.push(None);

    let reimburse_generator_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: reimburse_generator_tx.compute_txid(),
        tx: reimburse_generator_tx,
        prevouts: vec![
            sequential_collateral_txhandler.tx.output[0].clone(),
            sequential_collateral_txhandler.tx.output[1].clone(),
        ],
        prev_scripts: vec![
            sequential_collateral_txhandler.out_scripts[0].clone(),
            sequential_collateral_txhandler.out_scripts[1].clone(),
        ],
        prev_taproot_spend_infos: vec![
            sequential_collateral_txhandler.out_taproot_spend_infos[0].clone(),
            sequential_collateral_txhandler.out_taproot_spend_infos[1].clone(),
        ],
        out_scripts,
        out_taproot_spend_infos,
    }
}

/// Creates a [`TxHandler`] for the `kickoff_utxo_timeout_tx`. This transaction is sent when
/// the operator does not send the `kickoff_tx` within the timeout period (6 blocks), for a withdrawal
/// that they provided. Anyone will be able to burn the utxo after the timeout period.
pub fn create_kickoff_utxo_timeout_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 2 + kickoff_idx as u32,
        }]
        .into(),
    );

    let tx_outs = vec![builder::script::anchor_output()];

    let tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts: vec![sequential_collateral_txhandler.tx.output[2 + kickoff_idx].clone()],
        prev_scripts: vec![sequential_collateral_txhandler.out_scripts[2 + kickoff_idx].clone()],
        prev_taproot_spend_infos: vec![sequential_collateral_txhandler.out_taproot_spend_infos
            [2 + kickoff_idx]
            .clone()],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    }
}

/// Creates a [`TxHandler`] for the `kickoff_timeout_tx`. This transaction will be sent by anyone
/// in case the operator does not respond to a challenge (did not manage to send `assert_end_tx`)
/// in time, burning their burn connector.
pub fn create_kickoff_timeout_txhandler(
    kickoff_tx_handler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
    network: Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            OutPoint {
                txid: kickoff_tx_handler.txid,
                vout: 3,
            },
            OutPoint {
                txid: sequential_collateral_txhandler.txid,
                vout: 0,
            },
        ]
        .into(),
    );
    let (dust_address, _) = create_taproot_address(&[], None, network);
    let dust_output = TxOut {
        value: Amount::from_sat(330),
        script_pubkey: dust_address.script_pubkey(),
    };
    let anchor_output = builder::script::anchor_output();
    let tx_outs = vec![dust_output, anchor_output];
    let kickoff_timeout_tx = create_btc_tx(tx_ins, tx_outs);
    TxHandler {
        txid: kickoff_timeout_tx.compute_txid(),
        tx: kickoff_timeout_tx,
        prevouts: vec![
            kickoff_tx_handler.tx.output[3].clone(),
            sequential_collateral_txhandler.tx.output[0].clone(),
        ],
        prev_scripts: vec![
            kickoff_tx_handler.out_scripts[3].clone(),
            sequential_collateral_txhandler.out_scripts[0].clone(),
        ],
        prev_taproot_spend_infos: vec![
            kickoff_tx_handler.out_taproot_spend_infos[3].clone(),
            sequential_collateral_txhandler.out_taproot_spend_infos[0].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
}
