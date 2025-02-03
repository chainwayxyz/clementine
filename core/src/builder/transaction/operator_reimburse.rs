use crate::builder::address::create_taproot_address;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, TxHandlerBuilder};
use crate::builder::transaction::{create_btc_tx, create_tx_ins};
use crate::constants::{BRIDGE_AMOUNT_SATS, MIN_TAPROOT_AMOUNT};
use crate::{builder, utils};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Network, Sequence, TxOut, Txid};
use bitcoin::{OutPoint, XOnlyPublicKey};

/// Creates a [`TxHandler`] for the `kickoff_tx`. This transaction will be sent by the operator
pub fn create_kickoff_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    network: Network,
) -> TxHandler {
    let mut builder = TxHandlerBuilder::new();
    builder = builder.add_input(
        sequential_collateral_txhandler
            .get_spendable_output(2 + kickoff_idx)
            .unwrap(),
        Sequence::default(),
        None,
    );

    let (nofn_taproot_address, nofn_taproot_spend) =
        builder::address::create_checksig_address(nofn_xonly_pk, network);
    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: nofn_taproot_address.script_pubkey(),
        },
        vec![builder::script::generate_checksig_script(nofn_xonly_pk)],
        Some(nofn_taproot_spend),
    ));

    let operator_1week =
        builder::script::generate_checksig_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);
    let operator_2_5_week = builder::script::generate_checksig_relative_timelock_script(
        operator_xonly_pk,
        7 * 24 * 6 / 2 * 5,
    ); // 2.5 weeks
    let nofn_3week =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);

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
        vec![operator_1week.clone(), nofn_script.clone()],
        Some(nofn_or_operator_1week_spend),
    ));

    let (nofn_or_operator_2_5_week, nofn_or_operator_2_5_week_spend) =
        builder::address::create_taproot_address(
            &[operator_2_5_week.clone(), nofn_script.clone()],
            None,
            network,
        );

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: nofn_or_operator_2_5_week.script_pubkey(),
        },
        vec![operator_2_5_week.clone(), nofn_script.clone()],
        Some(nofn_or_operator_2_5_week_spend),
    ));

    let (nofn_or_nofn_3week, nofn_or_nofn_3week_spend) = builder::address::create_taproot_address(
        &[nofn_3week.clone(), nofn_script.clone()],
        None,
        network,
    );

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: nofn_or_nofn_3week.script_pubkey(),
        },
        vec![nofn_3week.clone(), nofn_script.clone()],
        Some(nofn_or_nofn_3week_spend),
    ));

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));

    let push_bytes = PushBytesBuf::try_from(op_return_script)
        .expect("Can't fail since the script is shorter than 4294967296 bytes");

    let op_return_txout = builder::script::op_return_txout(push_bytes);

    builder
        .add_output(UnspentTxOut::new(op_return_txout.clone(), vec![op_return_txout.script_pubkey], None))
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize()
}

/// Creates a [`TxHandler`] for the `start_happy_reimburse_tx`. This transaction will be sent by the operator
/// in case of no challenges, to be able to send `happy_reimburse_tx` later. Everyone is happy because the
/// operator is honest and the system does not have to deal with any disputes.
pub fn create_start_happy_reimburse_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let mut builder = TxHandlerBuilder::new();
    builder = builder.add_input(
        kickoff_txhandler.get_spendable_output(1).unwrap(),
        Sequence::from_height(7 * 24 * 6),
        None,
    );
    builder = builder.add_input(
        kickoff_txhandler.get_spendable_output(3).unwrap(),
        Sequence::default(),
        None,
    );

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    builder
        .add_output(UnspentTxOut::new(
            TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: op_address.script_pubkey(),
            },
            vec![],
            Some(op_spend),
        ))
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize()
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
    let mut builder = TxHandlerBuilder::new();
    builder = builder
        .add_input(
            move_txhandler.get_spendable_output(0).unwrap(),
            Sequence::default(),
            None,
        )
        .add_input(
            start_happy_reimburse_txhandler
                .get_spendable_output(0)
                .unwrap(),
            Sequence::default(),
            None,
        )
        .add_input(
            reimburse_generator_txhandler
                .get_spendable_output(1 + kickoff_idx)
                .unwrap(),
            Sequence::default(),
            None,
        );

    builder
        .add_output(UnspentTxOut::new(
            TxOut {
                value: move_txhandler.get_spendable_output(0).unwrap().get_prevout().value,
                script_pubkey: operator_reimbursement_address.script_pubkey(),
            },
            vec![],
            None,
        ))
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize()
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
    let mut builder = TxHandlerBuilder::new().add_input(
        move_txhandler.get_spendable_output(0).unwrap(),
        Sequence::default(),
        None,
    ).add_input(
        disprove_timeout_txhandler.get_spendable_output(0).unwrap(),
        Sequence::default(),
        None,
    ).add_input(
        reimburse_generator_txhandler.get_spendable_output(1 + kickoff_idx).unwrap(),
        Sequence::default(),
        None,
    );

    builder
        .add_output(UnspentTxOut::new(
            TxOut {
                value: move_txhandler.get_spendable_output(0).unwrap().get_prevout().value,
                script_pubkey: operator_reimbursement_address.script_pubkey(),
            },
            vec![],
            None,
        ))
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ))
        .finalize()
}
