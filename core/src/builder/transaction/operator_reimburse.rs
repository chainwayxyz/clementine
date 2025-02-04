use super::txhandler::DEFAULT_SEQUENCE;
use crate::builder::script::{CheckSig, TimelockScript};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, TxHandlerBuilder};
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::errors::BridgeError;
use crate::{builder, utils};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::{Network, Sequence, TxOut, Txid};
use std::sync::Arc;

/// Creates a [`TxHandler`] for the `kickoff_tx`. This transaction will be sent by the operator
pub fn create_kickoff_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    network: Network,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new();
    builder = builder.add_input(
        sequential_collateral_txhandler.get_spendable_output(2 + kickoff_idx)?,
        DEFAULT_SEQUENCE,
    );

    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));
    builder = builder.add_output(UnspentTxOut::from_scripts(
        MIN_TAPROOT_AMOUNT,
        vec![nofn_script.clone()],
        None,
        network,
    ));

    let operator_1week = Arc::new(TimelockScript::new(Some(operator_xonly_pk), 7 * 24 * 6));
    let operator_2_5_week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        7 * 24 * 6 / 2 * 5,
    ));
    let nofn_3week = Arc::new(TimelockScript::new(Some(nofn_xonly_pk), 3 * 7 * 24 * 6));

    builder = builder
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![operator_1week, nofn_script.clone()],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![operator_2_5_week, nofn_script.clone()],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_3week, nofn_script],
            None,
            network,
        ));

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));

    let push_bytes = PushBytesBuf::try_from(op_return_script)
        .expect("Can't fail since the script is shorter than 4294967296 bytes");

    let op_return_txout = builder::script::op_return_txout(push_bytes);

    Ok(builder
        .add_output(UnspentTxOut::from_partial(op_return_txout))
        .add_output(UnspentTxOut::from_partial(builder::script::anchor_output()))
        .finalize())
}

/// Creates a [`TxHandler`] for the `start_happy_reimburse_tx`. This transaction will be sent by the operator
/// in case of no challenges, to be able to send `happy_reimburse_tx` later. Everyone is happy because the
/// operator is honest and the system does not have to deal with any disputes.
pub fn create_start_happy_reimburse_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new();
    builder = builder.add_input(
        kickoff_txhandler.get_spendable_output(1)?,
        Sequence::from_height(7 * 24 * 6),
    );
    builder = builder.add_input(kickoff_txhandler.get_spendable_output(3)?, DEFAULT_SEQUENCE);

    Ok(builder
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![],
            Some(operator_xonly_pk),
            network,
        ))
        .add_output(UnspentTxOut::from_partial(builder::script::anchor_output()))
        .finalize())
}

/// Creates a [`TxHandler`] for the `happy_reimburse_tx`. This transaction will be sent by the operator
/// in case of no challenges, to reimburse the operator for their honest behavior.
pub fn create_happy_reimburse_txhandler(
    move_txhandler: &TxHandler,
    start_happy_reimburse_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_idx: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new();
    builder = builder
        .add_input(move_txhandler.get_spendable_output(0)?, DEFAULT_SEQUENCE)
        .add_input(
            start_happy_reimburse_txhandler.get_spendable_output(0)?,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            reimburse_generator_txhandler.get_spendable_output(1 + kickoff_idx)?,
            DEFAULT_SEQUENCE,
        );

    Ok(builder
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: move_txhandler.get_spendable_output(0)?.get_prevout().value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(builder::script::anchor_output()))
        .finalize())
}

/// Creates a [`TxHandler`] for the `reimburse_tx`. This transaction will be sent by the operator
/// in case of a challenge, to reimburse the operator for their honest behavior.
pub fn create_reimburse_txhandler(
    move_txhandler: &TxHandler,
    disprove_timeout_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_idx: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> Result<TxHandler, BridgeError> {
    let builder = TxHandlerBuilder::new()
        .add_input(move_txhandler.get_spendable_output(0)?, DEFAULT_SEQUENCE)
        .add_input(
            disprove_timeout_txhandler.get_spendable_output(0)?,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            reimburse_generator_txhandler.get_spendable_output(1 + kickoff_idx)?,
            DEFAULT_SEQUENCE,
        );

    Ok(builder
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: move_txhandler.get_spendable_output(0)?.get_prevout().value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(builder::script::anchor_output()))
        .finalize())
}
