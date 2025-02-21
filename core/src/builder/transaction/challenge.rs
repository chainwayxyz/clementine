use crate::builder;
use crate::builder::script::{PreimageRevealScript, SpendPath, TimelockScript, WinternitzCommit};
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, DEFAULT_SEQUENCE};
use crate::builder::transaction::*;
use crate::constants::{BLOCKS_PER_WEEK, MIN_TAPROOT_AMOUNT, OPERATOR_CHALLENGE_AMOUNT};
use crate::errors::BridgeError;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use bitcoin::{Amount, ScriptBuf, Sequence, TxOut, XOnlyPublicKey};
use std::sync::Arc;

/// Creates a "simplified "[`TxHandler`] for the `watchtower_challenge_kickoff_tx`. The purpose of the simplification
/// is that when the verifiers are generating related sighashes, they only need to know the output addresses or the
/// input UTXOs. They do not need to know output scripts or spendinfos.
pub fn create_watchtower_challenge_kickoff_txhandler(
    kickoff_tx_handler: &TxHandler,
    num_watchtowers: u32,
    watchtower_challenge_addresses: &[ScriptBuf],
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new(TransactionType::WatchtowerChallengeKickoff).add_input(
        NormalSignatureKind::WatchtowerChallengeKickoff,
        kickoff_tx_handler.get_spendable_output(0)?,
        SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );
    for i in 0..num_watchtowers {
        builder = builder.add_output(UnspentTxOut::new(
            TxOut {
                value: MIN_TAPROOT_AMOUNT * 2, // TODO: Hand calculate this
                script_pubkey: watchtower_challenge_addresses[i as usize].clone(),
            },
            vec![],
            None,
        ));
    }
    Ok(builder
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `watchtower_challenge_tx`. This transaction
/// is sent by the watchtowers to reveal their Groth16 proofs with their public
/// inputs for the longest chain proof, signed by the corresponding watchtowers
/// using WOTS. The output of this transaction can be spend by:
/// 1- the operator with revealing the preimage for the corresponding watchtower
/// 2- the NofN after 0.5 week `using kickoff_tx.output[2]`, which will also prevent
/// the operator from sending `assert_begin_tx`.
/// The revealed preimage will later be used to send `disprove_tx` if the operator
/// claims that the corresponding watchtower did not challenge them.
pub fn create_watchtower_challenge_txhandler(
    wck_txhandler: &TxHandler,
    watchtower_idx: usize,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    script: Option<Arc<WinternitzCommit>>,
) -> Result<TxHandler, BridgeError> {
    let prevout = wck_txhandler.get_spendable_output(watchtower_idx)?;
    let builder = TxHandlerBuilder::new(TransactionType::WatchtowerChallenge(watchtower_idx))
        .add_input(
            (
                NumberedSignatureKind::NumberedNotStored,
                watchtower_idx as i32,
            ),
            // if a script is not provided, that means this tx will not be signed so there doesn't need
            // to be actual script and spendinfo inside the txin
            // If we want to sign it we need to add the script inside the SpendableTxIn
            match script {
                None => prevout,
                Some(commit_script) => SpendableTxIn::from_scripts(
                    *prevout.get_prev_outpoint(),
                    prevout.get_prevout().value,
                    vec![commit_script],
                    None,
                    network,
                ),
            },
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        );

    let nofn_halfweek = Arc::new(TimelockScript::new(
        Some(nofn_xonly_pk),
        BLOCKS_PER_WEEK / 2,
    )); // 0.5 week
    let operator_with_preimage = Arc::new(PreimageRevealScript::new(
        operator_xonly_pk,
        *operator_unlock_hash,
    ));

    Ok(builder
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT, // TODO: Hand calculate this
            vec![operator_with_preimage, nofn_halfweek],
            None,
            network,
        ))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `operator_challenge_NACK_tx`. This transaction will force
/// the operator to reveal the preimage for the corresponding watchtower since if they do not
/// reveal the preimage, the NofN will be able to spend the output after 0.5 week, which will
/// prevent the operator from sending `assert_begin_tx`.
pub fn create_operator_challenge_nack_txhandler(
    watchtower_challenge_txhandler: &TxHandler,
    watchtower_idx: usize,
    kickoff_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(
        TxHandlerBuilder::new(TransactionType::OperatorChallengeNack(watchtower_idx))
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack1,
                    watchtower_idx as i32,
                ),
                watchtower_challenge_txhandler.get_spendable_output(0)?,
                SpendPath::ScriptSpend(1),
                Sequence::from_height(BLOCKS_PER_WEEK / 2),
            )
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack2,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler.get_spendable_output(2)?,
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
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the `operator_challenge_ACK_tx`. This transaction will is used so that
/// the operator can acknowledge the challenge and reveal the preimage for the corresponding watchtower.
/// If the operator does not reveal the preimage, the NofN will be able to spend the output after 0.5 week using
/// `operator_challenge_NACK_tx`.
pub fn create_operator_challenge_ack_txhandler(
    watchtower_challenge_txhandler: &TxHandler,
    watchtower_idx: usize,
) -> Result<TxHandler, BridgeError> {
    Ok(
        TxHandlerBuilder::new(TransactionType::OperatorChallengeAck(watchtower_idx))
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeAck,
                    watchtower_idx as i32,
                ),
                watchtower_challenge_txhandler.get_spendable_output(0)?,
                SpendPath::ScriptSpend(0),
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
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
            kickoff_txhandler.get_spendable_output(4)?,
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
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::Challenge)
        .add_input(
            NormalSignatureKind::Challenge,
            kickoff_txhandler.get_spendable_output(1)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: OPERATOR_CHALLENGE_AMOUNT,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(op_return_txout(b"TODO")))
        .finalize())
}

/// Creates a [`TxHandler`] for the `no challenge`. This transaction used when no one sends a
/// challenge tx, so that operator can spend kickoff finalizer to finalize the kickoff.
pub fn create_challenge_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::ChallengeTimeout)
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            kickoff_txhandler.get_spendable_output(1)?,
            SpendPath::ScriptSpend(1),
            Sequence::from_height(BLOCKS_PER_WEEK),
        )
        .add_input(
            NormalSignatureKind::ChallengeTimeout2,
            kickoff_txhandler.get_spendable_output(2)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}
