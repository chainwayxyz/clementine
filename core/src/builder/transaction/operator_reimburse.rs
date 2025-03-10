use super::input::SpendableTxIn;
use super::op_return_txout;
use super::txhandler::DEFAULT_SEQUENCE;
use super::Signed;
use super::TransactionType;
use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
use crate::builder::script::{CheckSig, SpendableScript, TimelockScript};
use crate::builder::script::{PreimageRevealScript, SpendPath};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, TxHandlerBuilder};
use crate::config::protocol::ProtocolParamset;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::KickoffId;
use crate::rpc::clementine::NormalSignatureKind;
use crate::{builder, utils::UTXO};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::OutPoint;
use bitcoin::XOnlyPublicKey;
use bitcoin::{Address, TapNodeHash, TxOut, Txid};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum AssertScripts<'a> {
    AssertScriptTapNodeHash(&'a [[u8; 32]]),
    AssertSpendableScript(Vec<Arc<dyn SpendableScript>>),
}

/// Creates a [`TxHandler`] for the `kickoff_tx`. This transaction will be sent by the operator
#[allow(clippy::too_many_arguments)]
pub fn create_kickoff_txhandler(
    kickoff_id: KickoffId,
    deposit_outpoint: OutPoint,
    round_txhandler: &TxHandler,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    // either actual SpendableScripts or scriptpubkeys from db
    assert_scripts: AssertScripts,
    disprove_root_hash: &[u8; 32],
    watchtower_challenge_root_hashes: &[[u8; 32]],
    operator_unlock_hashes: &[[u8; 20]],
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let kickoff_idx: usize = kickoff_id.kickoff_idx as usize;
    let operator_idx: usize = kickoff_id.operator_idx as usize;
    let move_txid: Txid = deposit_outpoint.txid;
    let mut builder =
        TxHandlerBuilder::new(TransactionType::Kickoff).with_version(Version::non_standard(3));
    builder = builder.add_input(
        NormalSignatureKind::OperatorSighashDefault,
        round_txhandler.get_spendable_output(1 + kickoff_idx)?,
        builder::script::SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));

    let operator_1week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        paramset.operator_challenge_timeout_timelock,
    ));

    builder = builder
        // goes to challenge tx or no challenge tx
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone(), operator_1week],
            None,
            paramset.network,
        ))
        // kickoff finalizer connector
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT * 20,
            vec![nofn_script.clone()],
            None,
            paramset.network,
        ))
        // UTXO to reimburse tx
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_script.clone()],
            None,
            paramset.network,
        ));

    // Add disprove utxo
    // Add Operator in 5 week script to taproot, that connects to disprove timeout
    let operator_5week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        paramset.disprove_timeout_timelock,
    ));
    let disprove_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, operator_5week.to_script_buf())
        .expect("taptree with one node at depth 1 will accept a script node")
        .add_hidden_node(1, TapNodeHash::from_byte_array(*disprove_root_hash))
        .expect("empty taptree will accept a node at depth 1")
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("Taproot with 2 nodes at depth 1 should be valid for disprove");

    let disprove_address = Address::p2tr(
        &SECP,
        *UNSPENDABLE_XONLY_PUBKEY,
        disprove_taproot_spend_info.merkle_root(),
        paramset.network,
    );

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: disprove_address.script_pubkey().clone(),
        },
        vec![operator_5week],
        Some(disprove_taproot_spend_info),
    ));

    // add nofn_4 week to all assert scripts
    let nofn_4week = Arc::new(TimelockScript::new(
        Some(nofn_xonly_pk),
        paramset.assert_timeout_timelock,
    ));

    match assert_scripts {
        AssertScripts::AssertScriptTapNodeHash(assert_script_hashes) => {
            for script_hash in assert_script_hashes.iter() {
                // Add N-of-N in 4 week script to taproot, that connects to assert timeout
                let assert_spend_info = TaprootBuilder::new()
                    .add_hidden_node(1, TapNodeHash::from_byte_array(*script_hash))
                    .expect("taptree with one node at depth 1 will accept a script node")
                    .add_leaf(1, nofn_4week.to_script_buf())
                    .expect("empty taptree will accept a node at depth 1")
                    .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
                    .expect("Taproot with 2 nodes at depth 1 should be valid for assert");

                let assert_address = Address::p2tr(
                    &SECP,
                    *UNSPENDABLE_XONLY_PUBKEY,
                    assert_spend_info.merkle_root(),
                    paramset.network,
                );

                builder = builder.add_output(UnspentTxOut::new(
                    TxOut {
                        value: MIN_TAPROOT_AMOUNT,
                        script_pubkey: assert_address.script_pubkey(),
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
                    paramset.network,
                ));
            }
        }
    }

    // create watchtower challenges
    if paramset.num_watchtowers != watchtower_challenge_root_hashes.len() {
        return Err(BridgeError::ConfigError(format!(
            "Number of watchtowers in config ({}) does not match number of watchtower challenge addresses ({})",
            paramset.num_watchtowers,
            watchtower_challenge_root_hashes.len()
        )));
    }

    if paramset.num_watchtowers != operator_unlock_hashes.len() {
        return Err(BridgeError::ConfigError(format!(
            "Number of watchtowers in config ({}) does not match number of operator unlock addresses ({})",
            paramset.num_watchtowers,
            operator_unlock_hashes.len()
        )));
    }

    for (watchtower_idx, script) in watchtower_challenge_root_hashes.iter().enumerate() {
        let nofn_2week = Arc::new(TimelockScript::new(
            Some(nofn_xonly_pk),
            paramset.watchtower_challenge_timeout_timelock,
        ));
        let wt_challenge_spendinfo = TaprootBuilder::new()
            .add_leaf(1, nofn_2week.to_script_buf())
            .expect("taptree with one node at depth 1 will accept a script node")
            .add_hidden_node(1, TapNodeHash::from_byte_array(*script))
            .expect("empty taptree will accept a node at depth 1")
            .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
            .expect("Taproot with 2 nodes at depth 1 should be valid for challenge");
        let wt_challenge_addr = Address::p2tr(
            &SECP,
            *UNSPENDABLE_XONLY_PUBKEY,
            wt_challenge_spendinfo.merkle_root(),
            paramset.network,
        );
        // UTXO for watchtower challenge or watchtower challenge timeouts
        builder = builder.add_output(UnspentTxOut::new(
            TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: wt_challenge_addr.script_pubkey(),
            },
            vec![nofn_2week.clone()],
            Some(wt_challenge_spendinfo),
        ));

        // UTXO for operator challenge ack, nack, and watchtower challenge timeouts
        let nofn_3week = Arc::new(TimelockScript::new(
            Some(nofn_xonly_pk),
            paramset.operator_challenge_nack_timelock,
        ));
        let operator_with_preimage = Arc::new(PreimageRevealScript::new(
            operator_xonly_pk,
            operator_unlock_hashes[watchtower_idx],
        ));
        builder = builder.add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![
                nofn_3week.clone(),
                nofn_2week.clone(),
                operator_with_preimage,
            ],
            None,
            paramset.network,
        ));
    }

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(crate::utils::usize_to_var_len_bytes(operator_idx));

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
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::KickoffNotFinalized1,
            kickoff_txhandler.get_spendable_output(1)?,
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
        .add_burn_output()
        .finalize())
}

/// Creates a [`TxHandler`] for the `reimburse_tx`. This transaction will be sent by the operator
/// in case of a challenge, to reimburse the operator for their honest behavior.
pub fn create_reimburse_txhandler(
    move_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
    kickoff_idx: usize,
    num_kickoffs_per_round: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> Result<TxHandler, BridgeError> {
    let builder = TxHandlerBuilder::new(TransactionType::Reimburse)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::Reimburse1,
            move_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::Reimburse2,
            kickoff_txhandler.get_spendable_output(2)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            round_txhandler.get_spendable_output(1 + kickoff_idx + num_kickoffs_per_round)?,
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
    _network: bitcoin::Network,
) -> Result<TxHandler<Signed>, BridgeError> {
    let user_sig_wrapped = bitcoin::taproot::Signature {
        signature: user_sig,
        sighash_type: bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
    };
    let txin = SpendableTxIn::new_partial(input_utxo.outpoint, input_utxo.txout);

    let output_txout = UnspentTxOut::from_partial(output_txout.clone());

    let op_return_txout = op_return_txout(
        PushBytesBuf::try_from(crate::utils::usize_to_var_len_bytes(operator_idx))
            .expect("operator idx size < 8 bytes"),
    );

    let mut txhandler = TxHandlerBuilder::new(TransactionType::Payout)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::NotStored,
            txin,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(output_txout)
        .add_output(UnspentTxOut::from_partial(op_return_txout))
        .finalize();
    txhandler.set_p2tr_key_spend_witness(&user_sig_wrapped, 0)?;
    txhandler.promote()
}
