use crate::builder;
use crate::builder::script::SpendPath;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::{TxHandler, DEFAULT_SEQUENCE};
use crate::builder::transaction::*;
use crate::config::protocol::ProtocolParamset;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use bitcoin::script::PushBytesBuf;
use bitcoin::{Sequence, TxOut, WitnessVersion};

use self::input::UtxoVout;

/// Creates a [`TxHandler`] for the `watchtower_challenge_tx`. This transaction
/// is sent by the watchtowers to reveal their Groth16 proofs with their public
/// inputs for the longest chain proof. The data is encoded as 32 byte script pubkeys
/// of taproot utxos, and a single at max 80 byte OP_RETURN utxo.
pub fn create_watchtower_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    commit_data: &[u8],
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    if commit_data.len() != paramset.watchtower_challenge_bytes {
        return Err(TxError::IncorrectWatchtowerChallengeDataLength.into());
    }
    let mut builder = TxHandlerBuilder::new(TransactionType::WatchtowerChallenge(watchtower_idx))
        .with_version(Version::non_standard(3))
        .add_input(
            (
                NumberedSignatureKind::WatchtowerChallenge,
                watchtower_idx as i32,
            ),
            kickoff_txhandler
                .get_spendable_output(UtxoVout::WatchtowerChallenge(watchtower_idx))?,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        );
    let mut current_idx = 0;
    while current_idx + 80 < paramset.watchtower_challenge_bytes {
        // encode next 32 bytes of data as script pubkey of taproot utxo
        let data = PushBytesBuf::try_from(commit_data[current_idx..current_idx + 32].to_vec())
            .map_err(|e| {
                eyre::eyre!(format!(
                    "Failed to create pushbytesbuf for watchtower challenge op_return: {}",
                    e
                ))
            })?;

        let data_encoded_scriptbuf = Builder::new()
            .push_opcode(WitnessVersion::V1.into())
            .push_slice(data)
            .into_script();

        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: data_encoded_scriptbuf,
        }));
        current_idx += 32;
    }

    // add the remaining data as an op_return output
    if current_idx < paramset.watchtower_challenge_bytes {
        let remaining_data =
            PushBytesBuf::try_from(commit_data[current_idx..].to_vec()).map_err(|e| {
                eyre::eyre!(format!(
                    "Failed to create pushbytesbuf for watchtower challenge op_return: {}",
                    e
                ))
            })?;
        builder = builder.add_output(UnspentTxOut::from_partial(op_return_txout(remaining_data)));
    }

    Ok(builder.finalize())
}

/// Creates the watchtower challenge timeout txhandler.
/// This tx needs to be sent by operators when a watchtower doesn't send a challenge,
/// otherwise operator will be forced to reveal their preimage.
pub fn create_watchtower_challenge_timeout_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let watchtower_challenge_vout = UtxoVout::WatchtowerChallenge(watchtower_idx);
    let challenge_ack_vout = UtxoVout::WatchtowerChallengeAck(watchtower_idx);
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
    Ok(
        TxHandlerBuilder::new(TransactionType::OperatorChallengeNack(watchtower_idx))
            .with_version(Version::non_standard(3))
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack1,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler
                    .get_spendable_output(UtxoVout::WatchtowerChallengeAck(watchtower_idx))?,
                SpendPath::ScriptSpend(0),
                Sequence::from_height(paramset.operator_challenge_nack_timelock),
            )
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack2,
                    watchtower_idx as i32,
                ),
                kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
                SpendPath::ScriptSpend(0),
                DEFAULT_SEQUENCE,
            )
            .add_input(
                (
                    NumberedSignatureKind::OperatorChallengeNack3,
                    watchtower_idx as i32,
                ),
                round_txhandler.get_spendable_output(UtxoVout::BurnConnector)?,
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
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    _paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    Ok(
        TxHandlerBuilder::new(TransactionType::OperatorChallengeAck(watchtower_idx))
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::OperatorChallengeAck1,
                kickoff_txhandler
                    .get_spendable_output(UtxoVout::WatchtowerChallengeAck(watchtower_idx))?,
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
        .with_version(Version::TWO)
        .add_input(
            NormalSignatureKind::NoSignature,
            kickoff_txhandler.get_spendable_output(UtxoVout::Disprove)?,
            SpendPath::Unknown,
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::Disprove2,
            round_txhandler.get_spendable_output(UtxoVout::BurnConnector)?,
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
            kickoff_txhandler.get_spendable_output(UtxoVout::Challenge)?,
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
            kickoff_txhandler.get_spendable_output(UtxoVout::Challenge)?,
            SpendPath::ScriptSpend(1),
            Sequence::from_height(paramset.operator_challenge_timeout_timelock),
        )
        .add_input(
            NormalSignatureKind::ChallengeTimeout2,
            kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}
