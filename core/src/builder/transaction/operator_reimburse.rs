use crate::builder::address::create_taproot_address;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::{create_btc_tx, create_tx_ins, create_tx_outs};
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::{builder, utils};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Network, TxOut, Txid};
use bitcoin::{OutPoint, XOnlyPublicKey};

use super::txhandler::{TxHandlerBuilder, Unsigned, UnspentTxOut, DEFAULT_SEQUENCE};

/// Creates a [`TxHandler`] for the `kickoff_tx`. This transaction will be sent by the operator
pub fn create_kickoff_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    network: Network,
) -> TxHandler<Unsigned> {
    let mut builder = TxHandlerBuilder::new();

    // Add input from sequential collateral
    builder =
        builder.add_input(sequential_collateral_txhandler.get_output_as_spendable(2 + kickoff_idx));

    // NofN keyspend
    let (nofn_taproot_address, nofn_taproot_spend) =
        builder::address::create_checksig_address(nofn_xonly_pk, network);

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: nofn_taproot_address.script_pubkey(),
        },
        vec![],
        nofn_taproot_spend,
    ));

    // NofN or Operator in 1 week
    let operator_1week =
        builder::script::generate_checksig_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);
    let nofn_script = builder::script::generate_checksig_script(nofn_xonly_pk);
    let (nofn_or_operator_1week, nofn_or_operator_1week_spend) =
        builder::address::create_taproot_address(
            &[operator_1week.clone(), nofn_script.clone()],
            None,
            network,
        );

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: nofn_or_operator_1week.script_pubkey(),
        },
        vec![operator_1week, nofn_script.clone()],
        nofn_or_operator_1week_spend,
    ));

    // Operator in 2.5 weeks
    let operator_2_5_week = builder::script::generate_checksig_relative_timelock_script(
        operator_xonly_pk,
        7 * 24 * 6 / 2 * 5,
    );
    let (operator_2_5_week_address, operator_2_5_week_spend) =
        builder::address::create_taproot_address(&[operator_2_5_week.clone()], None, network);

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: operator_2_5_week_address.script_pubkey(),
        },
        vec![operator_2_5_week],
        operator_2_5_week_spend,
    ));

    let nofn_3week =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);
    let (nofn_3week_address, nofn_3week_spend) =
        builder::address::create_taproot_address(&[nofn_3week.clone()], None, network);

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: nofn_3week_address.script_pubkey(),
        },
        vec![nofn_3week],
        nofn_3week_spend,
    ));

    // Add OP_RETURN output
    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));
    let push_bytes = PushBytesBuf::try_from(op_return_script)
        .expect("Can't fail since the script is shorter than 4294967296 bytes");

    builder = builder.add_output(UnspentTxOut::new_partial(builder::script::op_return_txout(
        push_bytes,
    )));

    builder = builder.add_output(UnspentTxOut::new_partial(builder::script::anchor_output()));

    builder.finalize()
}

/// Creates a [`TxHandler`] for the `start_happy_reimburse_tx`. This transaction will be sent by the operator
/// in case of no challenges, to be able to send `happy_reimburse_tx` later. Everyone is happy because the
/// operator is honest and the system does not have to deal with any disputes.
pub fn create_start_happy_reimburse_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            (
                OutPoint {
                    txid: kickoff_txhandler.txid,
                    vout: 1,
                },
                Some(7 * 24 * 6),
            ),
            (
                OutPoint {
                    txid: kickoff_txhandler.txid,
                    vout: 3,
                },
                None,
            ),
        ]
        .into(),
    );

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    let tx_outs = vec![
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: op_address.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let happy_reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: happy_reimburse_tx.compute_txid(),
        tx: happy_reimburse_tx,
        prevouts: vec![
            kickoff_txhandler.tx.output[1].clone(),
            kickoff_txhandler.tx.output[3].clone(),
        ],
        prev_scripts: vec![
            kickoff_txhandler.out_scripts[1].clone(),
            kickoff_txhandler.out_scripts[3].clone(),
        ],
        prev_taproot_spend_infos: vec![
            kickoff_txhandler.out_taproot_spend_infos[1].clone(),
            kickoff_txhandler.out_taproot_spend_infos[3].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![Some(op_spend), None],
    }
}

/// Creates a [`TxHandler`] for the `happy_reimburse_tx`. This transaction will be sent by the operator
/// in case of no challenges, to reimburse the operator for their honest behavior.
pub fn create_happy_reimburse_txhandler(
    move_txhandler: &TxHandler,
    start_happy_reimburse_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_idx: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> TxHandler<Unsigned> {
    let mut builder = TxHandlerBuilder::new();

    // Add move tx input
    builder = builder.add_input(move_txhandler.get_output_as_spendable(0));

    // Add start happy reimburse input
    builder = builder.add_input(start_happy_reimburse_txhandler.get_output_as_spendable(0));

    // Add reimburse generator input
    builder =
        builder.add_input(reimburse_generator_txhandler.get_output_as_spendable(1 + kickoff_idx));

    // Add reimbursement output
    builder = builder.add_output(UnspentTxOut::new_partial(TxOut {
        value: move_txhandler.get_output_as_spendable(0).value(),
        script_pubkey: operator_reimbursement_address.script_pubkey(),
    }));

    // Add anchor output
    builder = builder.add_output(UnspentTxOut::new_partial(builder::script::anchor_output()));

    builder.finalize()
}

/// Creates a [`TxHandler`] for the `reimburse_tx`. This transaction will be sent by the operator
/// in case of a challenge, to reimburse the operator for their honest behavior.
pub fn create_reimburse_txhandler(
    move_txhandler: &TxHandler,
    disprove_timeout_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_idx: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            OutPoint {
                txid: move_txhandler.txid,
                vout: 0,
            },
            OutPoint {
                txid: disprove_timeout_txhandler.txid,
                vout: 0,
            },
            OutPoint {
                txid: reimburse_generator_txhandler.txid,
                vout: 1 + kickoff_idx as u32,
            },
        ]
        .into(),
    );

    let tx_outs = vec![
        TxOut {
            // value in move_tx currently (bridge amount)
            value: move_txhandler.tx.output[0].value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: reimburse_tx.compute_txid(),
        tx: reimburse_tx,
        prevouts: vec![
            move_txhandler.tx.output[0].clone(),
            disprove_timeout_txhandler.tx.output[0].clone(),
            reimburse_generator_txhandler.tx.output[1 + kickoff_idx].clone(),
        ],
        prev_scripts: vec![
            move_txhandler.out_scripts[0].clone(),
            disprove_timeout_txhandler.out_scripts[0].clone(),
            reimburse_generator_txhandler.out_scripts[1 + kickoff_idx].clone(),
        ],
        prev_taproot_spend_infos: vec![
            move_txhandler.out_taproot_spend_infos[0].clone(),
            disprove_timeout_txhandler.out_taproot_spend_infos[0].clone(),
            reimburse_generator_txhandler.out_taproot_spend_infos[1 + kickoff_idx].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
}
