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
use bitcoin::{Address, Amount, Network, ScriptBuf, Sequence, TapNodeHash, TxOut, Txid};
use bitcoin::{Witness, XOnlyPublicKey};
use std::sync::Arc;
use bitcoin::taproot::TaprootBuilder;
use crate::utils::{SECP, UNSPENDABLE_XONLY_PUBKEY};

pub enum AssertScripts<'a> {
    AssertScriptTapNodeHash(&'a [[u8; 32]]),
    AssertSpendableScript(Vec<Arc<dyn SpendableScript>>),
}

/// Creates a [`TxHandler`] for the `kickoff_tx`. This transaction will be sent by the operator
pub fn create_kickoff_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    // either actual SpendableScripts or scriptpubkeys from db
    assert_scripts: AssertScripts,
    disprove_root_hash: &[u8; 32],
    network: Network,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new(TransactionType::Kickoff);
    builder = builder.add_input(
        NormalSignatureKind::OperatorSighashDefault,
        sequential_collateral_txhandler.get_spendable_output(1 + kickoff_idx)?,
        builder::script::SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));

    let operator_1week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        BLOCKS_PER_WEEK,
    ));

    builder = builder
        // goes to watchtower challenge kickoff
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone()],
            None,
            network,
        ))
        // goes to challenge tx or no challenge tx
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone(), operator_1week],
            None,
            network,
        ))
        // kickoff finalizer connector
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone()],
            None,
            network,
        ))
        // UTXO to reimburse tx
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone()],
            None,
            network,
        ));

    // Add disprove utxo
    // Add N-of-N in 5 week script to taproot, that connects to disprove timeout
    let disprove_taproot_spend_info = TaprootBuilder::new()
        .add_hidden_node(1, TapNodeHash::from_byte_array(*disprove_root_hash))
        .expect("empty taptree will accept a node at depth 1")
        .add_leaf(1, TimelockScript::new(Some(nofn_xonly_pk), BLOCKS_PER_WEEK * 5).to_script_buf())
        .expect("taptree with one node at depth 1 will accept a script node")
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("Taproot with 2 nodes at depth 1 should be valid for disprove");

    let disprove_address = Address::p2tr(
        &SECP,
        nofn_xonly_pk,
        disprove_taproot_spend_info.merkle_root(),
        network,
    );

    builder = builder
        .add_output(UnspentTxOut::new(
            TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: disprove_address.script_pubkey().clone(),
            },
            vec![Arc::new(CheckSig::new(nofn_xonly_pk))],
            Some(disprove_taproot_spend_info),
        ));

    // add nofn_4 week to all assert scripts
    let mut nofn_4week = Arc::new(TimelockScript::new(
        Some(nofn_xonly_pk),
        4 * BLOCKS_PER_WEEK,
    ));

    match assert_scripts {
        AssertScripts::AssertScriptTapNodeHash(assert_script_pubkeys) => {
            for script_hash in assert_script_pubkeys.into() {
                // Add N-of-N in 4 week script to taproot, that connects to assert timeout
                let assert_spend_info = TaprootBuilder::new()
                    .add_hidden_node(1, TapNodeHash::from_byte_array(script_hash))
                    .expect("empty taptree will accept a node at depth 1")
                    .add_leaf(1, TimelockScript::new(Some(nofn_xonly_pk), BLOCKS_PER_WEEK * 4).to_script_buf())
                    .expect("taptree with one node at depth 1 will accept a script node")
                    .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
                    .expect("Taproot with 2 nodes at depth 1 should be valid for assert");

                let assert_address = Address::p2tr(
                    &SECP,
                    nofn_xonly_pk,
                    assert_spend_info.merkle_root(),
                    network,
                );

                builder = builder.add_output(UnspentTxOut::new(
                    TxOut {
                        value: MIN_TAPROOT_AMOUNT,
                        script_pubkey: assert_address.script_pubkey().clone(),
                    },
                    vec![nofn_4week.clone()],
                    Some(assert_spend_info),
                ));
            }
        }
        AssertScripts::AssertSpendableScript(assert_scripts) => {
            for script in assert_scripts {
                builder = builder.add_output(UnspentTxOut::from_scripts(
                    MIN_TAPROOT_AMOUNT,
                    vec![nofn_4week.clone(), script],
                    None,
                    network,
                ));
            }
        }
    }

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

pub fn create_kickoff_not_finalized_txhandler(
    kickoff_txhandler: &TxHandler,
    ready_to_reimburse_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::KickoffNotFinalized)
        .add_input(
            NormalSignatureKind::KickoffNotFinalized1,
            kickoff_txhandler.get_spendable_output(2)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::KickoffNotFinalized2,
            ready_to_reimburse_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `reimburse_tx`. This transaction will be sent by the operator
/// in case of a challenge, to reimburse the operator for their honest behavior.
pub fn create_reimburse_txhandler(
    move_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
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
            NormalSignatureKind::Reimburse2,
            kickoff_txhandler.get_spendable_output(3)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
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
