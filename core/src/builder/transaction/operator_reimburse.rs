//! # Operator Reimburse Transactions
//!
//! This module contains the logic for creating operator reimbursement and payout-related transactions in the protocol.
//! These transactions handle the flow of funds for operator compensation, challenge handling, and user withdrawals.
//!
//! The main responsibilities include:
//! - Constructing the kickoff transaction, which sets up all outputs needed for subsequent protocol steps (challenge, reimbursement, asserts, etc.).
//! - Creating transactions for operator reimbursement in case of honest behavior.
//! - Handling payout transactions for user withdrawals, including both standard (with BitVM) and optimistic payout flows.
//!

use super::create_move_to_vault_txhandler;
use super::input::SpendableTxIn;
use super::input::UtxoVout;
use super::op_return_txout;
use super::txhandler::DEFAULT_SEQUENCE;
use super::HiddenNode;
use super::Signed;
use super::TransactionType;
use super::TxError;
use crate::builder::script::{CheckSig, SpendableScript, TimelockScript};
use crate::builder::script::{PreimageRevealScript, SpendPath};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, TxHandlerBuilder};
use crate::config::protocol::ProtocolParamset;
use crate::constants::NON_STANDARD_V3;
use crate::deposit::{DepositData, KickoffData};
use crate::errors::BridgeError;
use crate::rpc::clementine::NormalSignatureKind;
use crate::{builder, UTXO};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoin::{TxOut, Txid};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum AssertScripts<'a> {
    AssertScriptTapNodeHash(&'a [[u8; 32]]),
    AssertSpendableScript(Vec<Arc<dyn SpendableScript>>),
}

#[derive(Debug, Clone)]
pub enum DisprovePath<'a> {
    Scripts(Vec<ScriptBuf>),
    HiddenNode(HiddenNode<'a>),
}

/// Creates a [`TxHandler`] for the `kickoff_tx`.
///
/// This transaction is sent by the operator to initialize protocol state for a round, when operator fronted a peg-out and wants reimbursement. It sets up all outputs needed for subsequent protocol steps (challenge, reimbursement, asserts, etc.).
///
/// # Inputs
/// 1. RoundTx: Kickoff utxo (for the given kickoff index)
///
/// # Outputs
/// 1. Operator challenge output (for challenge or no-challenge path)
/// 2. Kickoff finalizer connector
/// 3. Reimburse connector (to be used in reimburse transaction)
/// 4. Disprove output (Taproot, for BitVM disprove path)
/// 5. Latest blockhash output (for latest blockhash assertion using winternitz signatures)
/// 6. Multiple assert outputs (for BitVM assertions, currently 36)
/// 7. For each watchtower 2 outputs:
///     - Watchtower challenge output
///     - Operator challenge ack/nack output
/// 8. OP_RETURN output (with move-to-vault txid and operator xonly pubkey)
/// 9. Anchor output for CPFP
///
/// # Arguments
/// * `kickoff_data` - Data to identify the kickoff.
/// * `round_txhandler` - The round transaction handler providing the input.
/// * `move_txhandler` - The move-to-vault transaction handler.
/// * `deposit_data` - Mutable reference to deposit data.
/// * `operator_xonly_pk` - The operator's x-only public key.
/// * `assert_scripts` - Actual assertion scripts or tapnode hashes (for faster creation of assert utxos) for BitVM assertion.
/// * `disprove_root_hash` - Root hash for BitVM disprove scripts.
/// * `additional_disprove_script` - Additional disprove script bytes (for additional disprove script specific to Clementine).
/// * `latest_blockhash_script` - Actual script or tapnode hash for latest blockhash assertion.
/// * `operator_unlock_hashes` - Unlock hashes for operator preimage reveals for OperatorChallengeAck transactions.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A [`TxHandler`] for the kickoff transaction, or a [`BridgeError`] if construction fails.
#[allow(clippy::too_many_arguments)]
pub fn create_kickoff_txhandler(
    kickoff_data: KickoffData,
    round_txhandler: &TxHandler,
    move_txhandler: &TxHandler,
    deposit_data: &mut DepositData,
    operator_xonly_pk: XOnlyPublicKey,
    assert_scripts: AssertScripts,
    disprove_path: DisprovePath,
    additional_disprove_script: Vec<u8>,
    latest_blockhash_script: AssertScripts,
    operator_unlock_hashes: &[[u8; 20]],
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let kickoff_idx = kickoff_data.kickoff_idx as usize;
    let move_txid: Txid = *move_txhandler.get_txid();
    let mut builder = TxHandlerBuilder::new(TransactionType::Kickoff).with_version(NON_STANDARD_V3);
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
            paramset.default_utxo_amount(),
            vec![operator_script, operator_1week],
            None,
            paramset.network,
        ))
        // kickoff finalizer connector
        .add_output(UnspentTxOut::from_scripts(
            paramset.default_utxo_amount(),
            vec![nofn_script.clone()],
            None,
            paramset.network,
        ))
        // UTXO to reimburse tx
        .add_output(UnspentTxOut::from_scripts(
            paramset.default_utxo_amount(),
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
        disprove_path,
        paramset.default_utxo_amount(),
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
                paramset.default_utxo_amount(),
                paramset.network,
            ));
        }
        AssertScripts::AssertSpendableScript(latest_blockhash_script) => {
            if latest_blockhash_script.len() != 1 {
                return Err(TxError::LatestBlockhashScriptNumber.into());
            }
            let latest_blockhash_script = latest_blockhash_script[0].clone();
            builder = builder.add_output(UnspentTxOut::from_scripts(
                paramset.default_utxo_amount(),
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
                    paramset.default_utxo_amount(),
                    paramset.network,
                ));
            }
        }
        AssertScripts::AssertSpendableScript(assert_scripts) => {
            for script in assert_scripts {
                builder = builder.add_output(UnspentTxOut::from_scripts(
                    paramset.default_utxo_amount(),
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
            paramset.default_utxo_amount() * 2 + paramset.anchor_amount(), // watchtower challenge has 2 taproot outputs, 1 op_return and 1 anchor
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
            paramset.default_utxo_amount(),
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
            builder::transaction::anchor_output(paramset.anchor_amount()),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `kickoff_not_finalized_tx`.
///
/// This transaction if an operator sends ReadyToReimburse transaction while not all kickoffs of the round are finalized, burning their collateral.
///
/// # Inputs
/// 1. KickoffTx: KickoffFinalizer utxo
/// 2. ReadyToReimburseTx: BurnConnector utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
/// * `kickoff_txhandler` - The kickoff transaction handler providing the input.
/// * `ready_to_reimburse_txhandler` - The ready-to-reimburse transaction handler providing the input.
///
/// # Returns
/// A [`TxHandler`] for the kickoff not finalized transaction, or a [`BridgeError`] if construction fails.
pub fn create_kickoff_not_finalized_txhandler(
    kickoff_txhandler: &TxHandler,
    ready_to_reimburse_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::KickoffNotFinalized)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::KickoffNotFinalized1,
            kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::KickoffNotFinalized2,
            ready_to_reimburse_txhandler
                .get_spendable_output(UtxoVout::CollateralInReadyToReimburse)?,
            builder::script::SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(paramset.anchor_amount()),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `reimburse_tx`.
///
/// This transaction is sent by the operator if no challenge was sent, or a challenge was sent but no disprove was sent, to reimburse the operator for their payout.
///
/// # Inputs
/// 1. MoveToVaultTx: Utxo containing the deposit
/// 2. KickoffTx: Reimburse connector utxo in the kickoff
/// 3. RoundTx: Reimburse connector utxo in the round (for the given kickoff index)
///
/// # Outputs
/// 1. Reimbursement output to the operator
/// 2. Anchor output for CPFP
///
/// # Arguments
/// * `move_txhandler` - The move-to-vault transaction handler for the deposit.
/// * `round_txhandler` - The round transaction handler for the round.
/// * `kickoff_txhandler` - The kickoff transaction handler for the kickoff.
/// * `kickoff_idx` - The kickoff index of the operator's kickoff.
/// * `paramset` - Protocol parameter set.
/// * `operator_reimbursement_address` - The address to reimburse the operator.
///
/// # Returns
/// A [`TxHandler`] for the reimburse transaction, or a [`BridgeError`] if construction fails.
pub fn create_reimburse_txhandler(
    move_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
    kickoff_idx: usize,
    paramset: &'static ProtocolParamset,
    operator_reimbursement_address: &bitcoin::Address,
) -> Result<TxHandler, BridgeError> {
    let builder = TxHandlerBuilder::new(TransactionType::Reimburse)
        .with_version(NON_STANDARD_V3)
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
            builder::transaction::anchor_output(paramset.anchor_amount()),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `payout_tx`.
///
/// This transaction is sent by the operator to front a peg-out, after which operator will send a kickoff transaction to get reimbursed.
///
/// # Inputs
/// 1. UTXO: User's withdrawal input (committed in Citrea side, with the signature given to operators off-chain)
///
/// # Outputs
/// 1. User payout output
/// 2. OP_RETURN output (with operators x-only pubkey that fronts the peg-out)
///
/// # Arguments
/// * `input_utxo` - The input UTXO for the payout, committed in Citrea side, with the signature given to operators off-chain.
/// * `output_txout` - The output TxOut for the user payout.
/// * `operator_xonly_pk` - The operator's x-only public key that fronts the peg-out.
/// * `user_sig` - The user's signature for the payout, given to operators off-chain.
/// * `network` - The Bitcoin network.
///
/// # Returns
/// A [`TxHandler`] for the payout transaction, or a [`BridgeError`] if construction fails.
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
        .with_version(NON_STANDARD_V3)
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

/// Creates a [`TxHandler`] for the `optimistic_payout_tx`.
///
/// This transaction is signed by all verifiers that participated in the corresponding deposit give the deposited funds directly to the user withdrawing from Citrea. This way no kickoff/BitVM process is needed.
///
/// # Inputs
/// 1. UTXO: User's withdrawal input (committed in Citrea side, with the signature given to operators off-chain)
/// 2. MoveToVaultTx: Utxo containing the deposit
///
/// # Outputs
/// 1. User payout output (to the user withdrawing from Citrea)
/// 2. Anchor output for CPFP
///
/// # Arguments
/// * `deposit_data` - Mutable reference to deposit data.
/// * `input_utxo` - The input UTXO for the payout, committed in Citrea side, with the signature given to operators off-chain.
/// * `output_txout` - The output TxOut for the user payout.
/// * `user_sig` - The user's signature for the payout, given to operators off-chain.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A [`TxHandler`] for the optimistic payout transaction, or a [`BridgeError`] if construction fails.
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
        .with_version(NON_STANDARD_V3)
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
            builder::transaction::non_ephemeral_anchor_output(),
        ))
        .finalize();
    txhandler.set_p2tr_key_spend_witness(&user_sig_wrapped, 0)?;
    Ok(txhandler)
}
