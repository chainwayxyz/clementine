use crate::builder;
use crate::builder::script::{SpendPath, TimelockScript, WinternitzCommit};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, DEFAULT_SEQUENCE};
use crate::builder::transaction::*;
use crate::config::protocol::ProtocolParamset;
use crate::errors::BridgeError;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use bitcoin::{Sequence, TxOut, XOnlyPublicKey};
use std::sync::Arc;

use super::input::{get_challenge_ack_vout, get_watchtower_challenge_utxo_vout};

/// Creates a [`TxHandler`] for the `watchtower_challenge_tx`. This transaction
/// is sent by the watchtowers to reveal their Groth16 proofs with their public
/// inputs for the longest chain proof, signed by the corresponding watchtowers
/// using WOTS.
pub fn create_watchtower_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    wots_script: Arc<WinternitzCommit>,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let prevout = kickoff_txhandler
        .get_spendable_output(get_watchtower_challenge_utxo_vout(watchtower_idx))?;
    let nofn_2week = Arc::new(TimelockScript::new(
        Some(nofn_xonly_pk),
        paramset.watchtower_challenge_timeout_timelock,
    ));
    Ok(
        TxHandlerBuilder::new(TransactionType::WatchtowerChallenge(watchtower_idx))
            .with_version(Version::non_standard(3))
            .add_input(
                (
                    NumberedSignatureKind::NumberedNotStored,
                    watchtower_idx as i32,
                ),
                SpendableTxIn::from_scripts(
                    *prevout.get_prev_outpoint(),
                    prevout.get_prevout().value,
                    vec![nofn_2week, wots_script],
                    None,
                    paramset.network,
                ),
                SpendPath::ScriptSpend(1),
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .add_output(UnspentTxOut::from_partial(op_return_txout(b"PADDING")))
            .finalize(),
    )
}

/// Creates the watchtower challenge timeout txhandler.
/// This tx needs to be sent by operators when a watchtower doesn't send a challenge,
/// otherwise operator will be forced to reveal their preimage.
pub fn create_watchtower_challenge_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let watchtower_challenge_vout = get_watchtower_challenge_utxo_vout(watchtower_idx);
    let challenge_ack_vout = get_challenge_ack_vout(watchtower_idx);
    Ok(
        TxHandlerBuilder::new(TransactionType::WatchtowerChallengeTimeout(watchtower_idx))
            .with_version(Version::non_standard(3))
            .add_input(
                (
                    NumberedSignatureKind::WatchtowerChallengeTimeout1,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler.get_spendable_output(watchtower_challenge_vout)?,
                SpendPath::ScriptSpend(0),
                Sequence::from_height(paramset.watchtower_challenge_timeout_timelock),
            )
            .add_input(
                (
                    NumberedSignatureKind::WatchtowerChallengeTimeout2,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler.get_spendable_output(challenge_ack_vout)?,
                SpendPath::ScriptSpend(1),
                Sequence::from_height(paramset.watchtower_challenge_timeout_timelock),
            )
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the `operator_challenge_NACK_tx`. This transaction will force
/// the operator to reveal the preimage for the corresponding watchtower since if they do not
/// reveal the preimage, the NofN will be able to spend the output after 0.5 week, which will
/// prevent the operator from sending `assert_begin_tx`.
pub fn create_operator_challenge_nack_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    round_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let challenge_ack_vout = get_challenge_ack_vout(watchtower_idx);

    Ok(
        TxHandlerBuilder::new(TransactionType::OperatorChallengeNack(watchtower_idx))
            .with_version(Version::non_standard(3))
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack1,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler.get_spendable_output(challenge_ack_vout)?,
                SpendPath::ScriptSpend(0),
                Sequence::from_height(paramset.operator_challenge_nack_timelock),
            )
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack2,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler.get_spendable_output(1)?,
                SpendPath::ScriptSpend(0),
                DEFAULT_SEQUENCE,
            )
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack3,
                    watchtower_idx as i32,
                ),
                round_txhandler.get_spendable_output(0)?,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .add_burn_output()
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the `operator_challenge_ACK_tx`. This transaction will is used so that
/// the operator can acknowledge the challenge and reveal the preimage for the corresponding watchtower.
/// If the operator does not reveal the preimage, the NofN will be able to spend the output after 0.5 week using
/// `operator_challenge_NACK_tx`.
pub fn create_operator_challenge_ack_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    _paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let challenge_ack_vout = get_challenge_ack_vout(watchtower_idx);
    Ok(
        TxHandlerBuilder::new(TransactionType::OperatorChallengeAck(watchtower_idx))
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::OperatorChallengeAck1,
                kickoff_txhandler.get_spendable_output(challenge_ack_vout)?,
                SpendPath::ScriptSpend(2),
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .add_output(UnspentTxOut::from_partial(op_return_txout(b"PADDING")))
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the `disprove_tx`. This transaction will be sent by NofN, meaning
/// that the operator was malicious. This transaction burns the operator's burn connector, kicking the
/// operator out of the system.
pub fn create_disprove_txhandler(
    kickoff_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::Disprove)
        .add_input(
            NormalSignatureKind::NoSignature,
            kickoff_txhandler.get_spendable_output(3)?,
            SpendPath::Unknown,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::Disprove2,
            round_txhandler.get_spendable_output(0)?,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `challenge`. This transaction is for covering
/// the operators' cost for a challenge to prevent people from maliciously
/// challenging them and causing them to lose money.
pub fn create_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_reimbursement_address: &bitcoin::Address,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::Challenge)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::Challenge,
            kickoff_txhandler.get_spendable_output(1)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: paramset.operator_challenge_amount,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(op_return_txout(b"TODO")))
        .finalize())
}

/// Creates a [`TxHandler`] for the `no challenge`. This transaction used when no one sends a
/// challenge tx, so that operator can spend kickoff finalizer to finalize the kickoff.
pub fn create_challenge_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::ChallengeTimeout)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            kickoff_txhandler.get_spendable_output(0)?,
            SpendPath::ScriptSpend(1),
            Sequence::from_height(paramset.operator_challenge_timeout_timelock),
        )
        .add_input(
            NormalSignatureKind::ChallengeTimeout2,
            kickoff_txhandler.get_spendable_output(1)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}
