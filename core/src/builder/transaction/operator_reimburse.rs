use super::input::SpendableTxIn;
use super::txhandler::DEFAULT_SEQUENCE;
use super::Signed;
use super::TransactionType;
use crate::builder::script::{CheckSig, SpendableScript, TimelockScript, WithdrawalScript};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, TxHandlerBuilder};
use crate::constants::{BLOCKS_PER_WEEK, MIN_TAPROOT_AMOUNT};
use crate::errors::BridgeError;
use crate::rpc::clementine::NormalSignatureKind;
use crate::{builder, utils, UTXO};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::{Amount, Network, Sequence, TxOut, Txid};
use bitcoin::{Witness, XOnlyPublicKey};
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
    let mut builder = TxHandlerBuilder::new(TransactionType::Kickoff);
    builder = builder.add_input(
        NormalSignatureKind::NotStored,
        sequential_collateral_txhandler.get_spendable_output(2 + kickoff_idx)?,
        builder::script::SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));

    let operator_1week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        BLOCKS_PER_WEEK,
    ));
    let operator_2_5_week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        BLOCKS_PER_WEEK / 2 * 5, // 2.5 weeks
    ));
    let nofn_3week = Arc::new(TimelockScript::new(
        Some(nofn_xonly_pk),
        3 * BLOCKS_PER_WEEK,
    ));

    builder = builder
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone()],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone(), operator_1week],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone(), operator_2_5_week],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script, nofn_3week],
            None,
            network,
        ));

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));

    let push_bytes = PushBytesBuf::try_from(op_return_script)
        .expect("Can't fail since the script is shorter than 4294967296 bytes");

    let op_return_txout = builder::transaction::op_return_txout(push_bytes);

    Ok(builder
        .add_output(UnspentTxOut::from_partial(op_return_txout))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
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
    let mut builder = TxHandlerBuilder::new(TransactionType::StartHappyReimburse);
    builder = builder.add_input(
        NormalSignatureKind::NotStored,
        kickoff_txhandler.get_spendable_output(1)?,
        builder::script::SpendPath::ScriptSpend(1),
        Sequence::from_height(BLOCKS_PER_WEEK),
    );
    builder = builder.add_input(
        NormalSignatureKind::StartHappyReimburse2,
        kickoff_txhandler.get_spendable_output(3)?,
        builder::script::SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    Ok(builder
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![],
            Some(operator_xonly_pk),
            network,
        ))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
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
    let mut builder = TxHandlerBuilder::new(TransactionType::HappyReimburse);
    builder = builder
        .add_input(
            NormalSignatureKind::HappyReimburse1,
            move_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::NotStored,
            start_happy_reimburse_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::NotStored,
            reimburse_generator_txhandler.get_spendable_output(1 + kickoff_idx)?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        );

    Ok(builder
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: move_txhandler.get_spendable_output(0)?.get_prevout().value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
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
    let builder = TxHandlerBuilder::new(TransactionType::Reimburse)
        .add_input(
            NormalSignatureKind::Reimburse1,
            move_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::NotStored,
            disprove_timeout_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::NotStored,
            reimburse_generator_txhandler.get_spendable_output(1 + kickoff_idx)?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        );

    Ok(builder
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: move_txhandler.get_spendable_output(0)?.get_prevout().value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `payout_tx`. This transaction will be sent by the operator
/// for withdrawals.
pub fn create_payout_txhandler(
    input_utxo: UTXO,
    output_txout: TxOut,
    operator_idx: usize,
    user_sig: Signature,
    network: bitcoin::Network,
) -> Result<TxHandler<Signed>, BridgeError> {
    let user_sig_wrapped = bitcoin::taproot::Signature {
        signature: user_sig,
        sighash_type: bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
    };
    let witness = Witness::p2tr_key_spend(&user_sig_wrapped);
    let txin = SpendableTxIn::new_partial(input_utxo.outpoint, input_utxo.txout);

    let output_txout = UnspentTxOut::from_partial(output_txout.clone());

    let scripts: Vec<Arc<dyn SpendableScript>> =
        vec![Arc::new(WithdrawalScript::new(operator_idx))];
    let op_return_txout = UnspentTxOut::from_scripts(Amount::from_sat(0), scripts, None, network);

    TxHandlerBuilder::new(TransactionType::Payout)
        .add_input_with_witness(txin, DEFAULT_SEQUENCE, witness)
        .add_output(output_txout)
        .add_output(op_return_txout)
        .finalize_signed()
}
