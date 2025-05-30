use super::create_move_to_vault_txhandler;
use super::input::SpendableTxIn;
use super::input::UtxoVout;
use super::op_return_txout;
use super::txhandler::DEFAULT_SEQUENCE;
use super::Signed;
use super::TransactionType;
use super::TxError;
use crate::builder::script::{CheckSig, SpendableScript, TimelockScript};
use crate::builder::script::{PreimageRevealScript, SpendPath};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, TxHandlerBuilder};
use crate::config::protocol::ProtocolParamset;
use crate::constants::ANCHOR_AMOUNT;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::deposit::{DepositData, KickoffData};
use crate::errors::BridgeError;
use crate::rpc::clementine::NormalSignatureKind;
use crate::{builder, UTXO};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::transaction::Version;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::{TxOut, Txid};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum AssertScripts<'a> {
    AssertScriptTapNodeHash(&'a [[u8; 32]]),
    AssertSpendableScript(Vec<Arc<dyn SpendableScript>>),
}

/// Creates a [`TxHandler`] for the `kickoff_tx`. This transaction will be sent by the operator
pub fn create_kickoff_txhandler(
    kickoff_data: KickoffData,
    round_txhandler: &TxHandler,
    move_txhandler: &TxHandler,
    deposit_data: &mut DepositData,
    operator_xonly_pk: XOnlyPublicKey,
    // either actual SpendableScripts or scriptpubkeys from db
    assert_scripts: AssertScripts,
    disprove_root_hash: &[u8; 32],
    additional_disprove_script: Vec<u8>,
    latest_blockhash_script: AssertScripts,
    operator_unlock_hashes: &[[u8; 20]],
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let kickoff_idx = kickoff_data.kickoff_idx as usize;
    let move_txid: Txid = *move_txhandler.get_txid();
    let mut builder =
        TxHandlerBuilder::new(TransactionType::Kickoff).with_version(Version::non_standard(3));
    builder = builder.add_input(
        NormalSignatureKind::OperatorSighashDefault,
        round_txhandler.get_spendable_output(UtxoVout::Kickoff(kickoff_idx))?,
        builder::script::SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    let nofn_script = Arc::new(CheckSig::new(deposit_data.get_nofn_xonly_pk()?));
    let operator_script = Arc::new(CheckSig::new(operator_xonly_pk));

    let operator_1week = Arc::new(TimelockScript::new(
        Some(operator_xonly_pk),
        paramset.operator_challenge_timeout_timelock,
    ));

    builder = builder
        // goes to challenge tx or no challenge tx
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![operator_script, operator_1week],
            None,
            paramset.network,
        ))
        // kickoff finalizer connector
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
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

    let additional_disprove_script = ScriptBuf::from_bytes(additional_disprove_script);

    // disprove utxo
    builder = builder.add_output(super::create_disprove_taproot_output(
        operator_5week,
        additional_disprove_script.clone(),
        disprove_root_hash,
        MIN_TAPROOT_AMOUNT,
        paramset.network,
    ));

    let nofn_latest_blockhash = Arc::new(TimelockScript::new(
        Some(deposit_data.get_nofn_xonly_pk()?),
        paramset.latest_blockhash_timeout_timelock,
    ));

    match latest_blockhash_script {
        AssertScripts::AssertScriptTapNodeHash(latest_blockhash_root_hash) => {
            if latest_blockhash_root_hash.len() != 1 {
                return Err(TxError::LatestBlockhashScriptNumber.into());
            }
            let latest_blockhash_root_hash = latest_blockhash_root_hash[0];
            // latest blockhash utxo
            builder = builder.add_output(super::create_taproot_output_with_hidden_node(
                nofn_latest_blockhash,
                &latest_blockhash_root_hash,
                MIN_TAPROOT_AMOUNT,
                paramset.network,
            ));
        }
        AssertScripts::AssertSpendableScript(latest_blockhash_script) => {
            if latest_blockhash_script.len() != 1 {
                return Err(TxError::LatestBlockhashScriptNumber.into());
            }
            let latest_blockhash_script = latest_blockhash_script[0].clone();
            builder = builder.add_output(UnspentTxOut::from_scripts(
                MIN_TAPROOT_AMOUNT,
                vec![nofn_latest_blockhash, latest_blockhash_script],
                None,
                paramset.network,
            ));
        }
    }

    // add nofn_4 week to all assert scripts
    let nofn_4week = Arc::new(TimelockScript::new(
        Some(deposit_data.get_nofn_xonly_pk()?),
        paramset.assert_timeout_timelock,
    ));

    match assert_scripts {
        AssertScripts::AssertScriptTapNodeHash(assert_script_hashes) => {
            for script_hash in assert_script_hashes.iter() {
                // Add N-of-N in 4 week script to taproot, that connects to assert timeout
                builder = builder.add_output(super::create_taproot_output_with_hidden_node(
                    nofn_4week.clone(),
                    script_hash,
                    MIN_TAPROOT_AMOUNT,
                    paramset.network,
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

    let watchtower_xonly_pks = deposit_data.get_watchtowers();

    for (watchtower_idx, watchtower_xonly_pk) in watchtower_xonly_pks.iter().enumerate() {
        let nofn_2week = Arc::new(TimelockScript::new(
            Some(deposit_data.get_nofn_xonly_pk()?),
            paramset.watchtower_challenge_timeout_timelock,
        ));
        // UTXO for watchtower challenge or watchtower challenge timeouts
        builder = builder.add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT * 2 + ANCHOR_AMOUNT, // watchtower challenge has 2 taproot outputs, 1 op_return and 1 anchor
            vec![nofn_2week.clone()],
            Some(*watchtower_xonly_pk), // key path as watchtowers xonly pk
            paramset.network,
        ));

        // UTXO for operator challenge ack, nack, and watchtower challenge timeouts
        let nofn_3week = Arc::new(TimelockScript::new(
            Some(deposit_data.get_nofn_xonly_pk()?),
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
    op_return_script.extend(kickoff_data.operator_xonly_pk.serialize());

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
            kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::KickoffNotFinalized2,
            ready_to_reimburse_txhandler.get_spendable_output(UtxoVout::BurnConnector)?,
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
    round_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
    kickoff_idx: usize,
    paramset: &'static ProtocolParamset,
    operator_reimbursement_address: &bitcoin::Address,
) -> Result<TxHandler, BridgeError> {
    let builder = TxHandlerBuilder::new(TransactionType::Reimburse)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::Reimburse1,
            move_txhandler.get_spendable_output(UtxoVout::DepositInMove)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::Reimburse2,
            kickoff_txhandler.get_spendable_output(UtxoVout::ReimburseInKickoff)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            round_txhandler
                .get_spendable_output(UtxoVout::ReimburseInRound(kickoff_idx, paramset))?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        );

    Ok(builder
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: move_txhandler
                .get_spendable_output(UtxoVout::DepositInMove)?
                .get_prevout()
                .value,
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
    operator_xonly_pk: XOnlyPublicKey,
    user_sig: Signature,
    _network: bitcoin::Network,
) -> Result<TxHandler<Signed>, BridgeError> {
    let user_sig_wrapped = bitcoin::taproot::Signature {
        signature: user_sig,
        sighash_type: bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
    };
    let txin = SpendableTxIn::new_partial(input_utxo.outpoint, input_utxo.txout);

    let output_txout = UnspentTxOut::from_partial(output_txout.clone());

    let op_return_txout = op_return_txout(PushBytesBuf::from(operator_xonly_pk.serialize()));

    let mut txhandler = TxHandlerBuilder::new(TransactionType::Payout)
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

/// Creates a [`TxHandler`] for the `optimistic_payout_tx`. This transaction will be signed by all verifiers that participated in the corresponding deposit to directly payout without any kickoff.
pub fn create_optimistic_payout_txhandler(
    deposit_data: &mut DepositData,
    input_utxo: UTXO,
    output_txout: TxOut,
    user_sig: Signature,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let move_txhandler: TxHandler = create_move_to_vault_txhandler(deposit_data, paramset)?;
    let user_sig_wrapped = bitcoin::taproot::Signature {
        signature: user_sig,
        sighash_type: bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
    };
    let txin = SpendableTxIn::new_partial(input_utxo.outpoint, input_utxo.txout);

    let output_txout = UnspentTxOut::from_partial(output_txout.clone());

    let mut txhandler = TxHandlerBuilder::new(TransactionType::Payout)
        .add_input(
            NormalSignatureKind::NotStored,
            txin,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::NotStored,
            move_txhandler.get_spendable_output(UtxoVout::DepositInMove)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(output_txout)
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize();
    txhandler.set_p2tr_key_spend_witness(&user_sig_wrapped, 0)?;
    Ok(txhandler)
}
