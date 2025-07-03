//! # Challenge Transaction Logic
//!
//! This module provides functions for constructing and challenge related transactions in the protocol.
//! The transactions are: Challenge, ChallengeTimeout, OperatorChallengeNack, OperatorChallengeAck, Disprove.

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
use eyre::Context;

use self::input::UtxoVout;

/// Creates a [`TxHandler`] for the `watchtower_challenge_tx`.
///
/// This transaction is sent by a watchtower to submit a challenge proof (e.g., a Groth16 proof with public inputs).
/// The proof data is encoded as a series of Taproot outputs and a final OP_RETURN output.
/// Currently a watchtower challenge is in total 144 bytes, 32 + 32 + 80 bytes.
///
/// # Inputs
/// 1. KickoffTx: WatchtowerChallenge utxo (for the given watchtower)
///
/// # Outputs
/// 1. First output, first 32 bytes of challenge data encoded directly in scriptpubkey.
/// 2. Second output, next 32 bytes of challenge data encoded directly in scriptpubkey.
/// 3. OP_RETURN output, containing the last 80 bytes of challenge data.
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler the watchtower challenge belongs to.
/// * `watchtower_idx` - The index of the watchtower in the deposit submitting the challenge.
/// * `commit_data` - The challenge proof data to be included in the transaction.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the watchtower challenge transaction, or a [`BridgeError`] if construction fails.
pub fn create_watchtower_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    commit_data: &[u8],
    paramset: &'static ProtocolParamset,
    #[cfg(test)] test_params: &crate::config::TestParams,
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
            .wrap_err("Failed to create pushbytesbuf for watchtower challenge op_return: {}")?;

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
        let remaining_data = PushBytesBuf::try_from(commit_data[current_idx..].to_vec())
            .wrap_err("Failed to create pushbytesbuf for watchtower challenge op_return")?;
        builder = builder.add_output(UnspentTxOut::from_partial(op_return_txout(remaining_data)));
    }

    #[cfg(test)]
    {
        if test_params.use_large_annex_and_output {
            let mut op_return_vec: Vec<u8> = vec![0x6a, 0xa8, 0xcc, 0x03, 0x00];
            op_return_vec.extend_from_slice(&[0u8; 249000]);
            let additional_op_return_txout = TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(op_return_vec),
            };
            builder = builder.add_output(UnspentTxOut::from_partial(additional_op_return_txout));
        } else if test_params.use_large_output {
            let mut op_return_vec: Vec<u8> = vec![0x6a, 0x58, 0x3e, 0x0f, 0x00];
            op_return_vec.extend_from_slice(&[0u8; 999000]);
            let additional_op_return_txout = TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(op_return_vec),
            };
            builder = builder.add_output(UnspentTxOut::from_partial(additional_op_return_txout));
        }
    }

    Ok(builder.finalize())
}

/// Creates a [`TxHandler`] for the `watchtower_challenge_timeout_tx`.
///
/// This transaction is sent by an operator if a watchtower does not submit a challenge in time, allowing the operator to claim a timeout.
/// This way, operators do not need to reveal their preimage, and do not need to use the watchtowers longest chain proof in their
/// bridge proof.
///
/// # Inputs
/// 1. KickoffTx: WatchtowerChallenge utxo (for the given watchtower)
/// 2. KickoffTx: WatchtowerChallengeAck utxo (for the given watchtower)
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler the watchtower challenge timeout belongs to.
/// * `watchtower_idx` - The index of the watchtower in the deposit submitting the challenge.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the watchtower challenge timeout transaction, or a [`BridgeError`] if construction fails.
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
                builder::transaction::anchor_output(paramset.anchor_amount()),
            ))
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the `OperatorChallengeNack` transaction.
///
/// This transaction is used to force an operator to reveal a preimage for a watchtower challenge. If a watchtower sends a watchtower challenge,
/// but the operator does not reveal the preimage by sending an OperatorChallengeAck, after a specified number of time (defined in paramset),
/// the N-of-N can spend the output, burning the operator's collateral.
///
/// # Inputs
/// 1. KickoffTx: WatchtowerChallengeAck utxo (for the given watchtower)
/// 2. KickoffTx: KickoffFinalizer utxo
/// 3. RoundTx: BurnConnector utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler the operator challenge nack belongs to.
/// * `watchtower_idx` - The index of the watchtower in the deposit corresponding to the watchtower challenge related to the operator challenge nack.
/// * `round_txhandler` - The round transaction handler for the current round the kickoff belongs to.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the operator challenge NACK transaction, or a [`BridgeError`] if construction fails.
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
                round_txhandler.get_spendable_output(UtxoVout::CollateralInRound)?,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(paramset.anchor_amount()),
            ))
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the OperatorChallengeAck transaction.
///
/// This transaction is used by an operator to acknowledge a watchtower challenge and reveal the required preimage, if a watchtower challenge is sent.
///
/// # Inputs
/// 1. KickoffTx: WatchtowerChallengeAck utxo (for the given watchtower)
///
/// # Outputs
/// 1. Anchor output for CPFP
/// 2. Dummy OP_RETURN output (to pad the size of the transaction, as it is too small otherwise)
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler the operator challenge ack belongs to.
/// * `watchtower_idx` - The index of the watchtower that sent the challenge.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the operator challenge ACK transaction, or a [`BridgeError`] if construction fails.
pub fn create_operator_challenge_ack_txhandler(
    kickoff_txhandler: &TxHandler,
    watchtower_idx: usize,
    paramset: &'static ProtocolParamset,
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
                builder::transaction::anchor_output(paramset.anchor_amount()),
            ))
            .add_output(UnspentTxOut::from_partial(op_return_txout(b"PADDING")))
            .finalize(),
    )
}

/// Creates a [`TxHandler`] for the `disprove_tx`.
///
/// This transaction is sent by N-of-N to penalize a malicious operator by burning their collateral (burn connector).
/// This is done either with the additional disprove script created by BitVM, in case the public inputs of the bridge proof the operator
/// sent are not correct/do not match previous data, or if the Groth16 verification of the proof is incorrect using BitVM disprove scripts.
///
/// # Inputs
/// 1. KickoffTx: Disprove utxo
/// 2. RoundTx: BurnConnector utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler the disprove belongs to.
/// * `round_txhandler` - The round transaction handler to the current round the kickoff belongs to.
///
/// # Returns
///
/// A [`TxHandler`] for the disprove transaction, or a [`BridgeError`] if construction fails.
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
            round_txhandler.get_spendable_output(UtxoVout::CollateralInRound)?,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::non_ephemeral_anchor_output(), // must be non-ephemeral, because tx is v2
        ))
        .finalize())
}

/// Creates a [`TxHandler`] for the `challenge` transaction.
///
/// This transaction is used to reimburse an operator for a valid challenge, intended to cover their costs for sending asserts transactions,
/// and potentially cover their opportunity cost as their reimbursements are delayed due to the challenge. This cost of a challenge is also
/// used to disincentivize sending challenges for kickoffs that are correct. In case the challenge is correct and operator is proved to be
/// malicious, the challenge cost will be reimbursed using the operator's collateral that's locked in Citrea.
///
/// # Inputs
/// 1. KickoffTx: Challenge utxo
///
/// # Outputs
/// 1. Operator reimbursement output
/// 2. OP_RETURN output (containing EVM address of the challenger, for reimbursement if the challenge is correct)
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler that the challenge belongs to.
/// * `operator_reimbursement_address` - The address to reimburse the operator to cover their costs.
/// * `challenger_evm_address` - The EVM address of the challenger, for reimbursement if the challenge is correct.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the challenge transaction, or a [`BridgeError`] if construction fails.
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
        .finalize())
}

/// Creates a [`TxHandler`] for the `challenge_timeout` transaction.
///
/// This transaction is used to finalize a kickoff if no challenge is submitted in time, allowing the operator to proceed faster to the next round, thus getting their reimbursement, as the next round will generate the reimbursement connectors of the current round.
///
/// # Inputs
/// 1. KickoffTx: Challenge utxo
/// 2. KickoffTx: KickoffFinalizer utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
///
/// * `kickoff_txhandler` - The kickoff transaction handler the challenge timeout belongs to.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the challenge timeout transaction, or a [`BridgeError`] if construction fails.
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
            builder::transaction::anchor_output(paramset.anchor_amount()),
        ))
        .finalize())
}
