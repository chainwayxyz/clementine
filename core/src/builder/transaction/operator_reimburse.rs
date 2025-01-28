use crate::builder::address::create_taproot_address;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::{create_btc_tx, create_tx_ins, create_tx_outs};
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::{builder, utils};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::{Network, TxOut, Txid};
use bitcoin::{OutPoint, XOnlyPublicKey};

pub fn create_kickoff_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    network: Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 2 + kickoff_idx as u32,
        }]
        .into(),
    );
    let operator_1week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);
    let operator_2_5_week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6 / 2 * 5); // 2.5 weeks
    let nofn_3week =
        builder::script::generate_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);

    let (nofn_or_operator_1week, nofn_or_operator_1week_spend) =
        builder::address::create_taproot_address(
            &[operator_1week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (nofn_or_operator_2_5_week, nofn_or_operator_2_5_week_spend) =
        builder::address::create_taproot_address(
            &[operator_2_5_week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (nofn_or_nofn_3week, nofn_or_nofn_3week_spend) = builder::address::create_taproot_address(
        &[nofn_3week.clone()],
        Some(nofn_xonly_pk),
        network,
    );

    let (nofn_taproot_address, nofn_taproot_spend) =
        builder::address::create_musig2_address(nofn_xonly_pk, network);

    let mut tx_outs = create_tx_outs(vec![
        (MIN_TAPROOT_AMOUNT, nofn_taproot_address.script_pubkey()),
        (MIN_TAPROOT_AMOUNT, nofn_or_operator_1week.script_pubkey()),
        (
            MIN_TAPROOT_AMOUNT,
            nofn_or_operator_2_5_week.script_pubkey(),
        ),
        (MIN_TAPROOT_AMOUNT, nofn_or_nofn_3week.script_pubkey()),
    ]);
    tx_outs.push(builder::script::anchor_output());

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));
    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(&op_return_script).unwrap();
    let op_return_txout = builder::script::op_return_txout(push_bytes);
    tx_outs.push(op_return_txout);

    let tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts: vec![sequential_collateral_txhandler.tx.output[2 + kickoff_idx].clone()],
        prev_scripts: vec![sequential_collateral_txhandler.out_scripts[2 + kickoff_idx].clone()],
        prev_taproot_spend_infos: vec![sequential_collateral_txhandler.out_taproot_spend_infos
            [2 + kickoff_idx]
            .clone()],
        out_scripts: vec![
            vec![],
            vec![operator_1week],
            vec![operator_2_5_week],
            vec![nofn_3week],
            vec![],
            vec![],
        ],
        out_taproot_spend_infos: vec![
            Some(nofn_taproot_spend),
            Some(nofn_or_operator_1week_spend),
            Some(nofn_or_operator_2_5_week_spend),
            Some(nofn_or_nofn_3week_spend),
            None,
            None,
        ],
    }
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
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            OutPoint {
                txid: move_txhandler.txid,
                vout: 0,
            },
            OutPoint {
                txid: start_happy_reimburse_txhandler.txid,
                vout: 0,
            },
            OutPoint {
                txid: reimburse_generator_txhandler.txid,
                vout: 1 + kickoff_idx as u32,
            },
        ]
        .into(),
    );

    let anchor_txout = builder::script::anchor_output();
    let tx_outs = vec![
        TxOut {
            value: move_txhandler.tx.output[0].value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        },
        anchor_txout.clone(),
    ];

    let happy_reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: happy_reimburse_tx.compute_txid(),
        tx: happy_reimburse_tx,
        prevouts: vec![
            move_txhandler.tx.output[0].clone(),
            start_happy_reimburse_txhandler.tx.output[0].clone(),
            reimburse_generator_txhandler.tx.output[1 + kickoff_idx].clone(),
        ],
        prev_scripts: vec![
            move_txhandler.out_scripts[0].clone(),
            start_happy_reimburse_txhandler.out_scripts[0].clone(),
            reimburse_generator_txhandler.out_scripts[1 + kickoff_idx].clone(),
        ],
        prev_taproot_spend_infos: vec![
            move_txhandler.out_taproot_spend_infos[0].clone(),
            start_happy_reimburse_txhandler.out_taproot_spend_infos[0].clone(),
            reimburse_generator_txhandler.out_taproot_spend_infos[1 + kickoff_idx].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
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
