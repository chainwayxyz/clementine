use crate::{
    config::BridgeConfig,
    protocol::{
        ids::{Input, KickoffIdx, RoundIdx, TransactionType},
        tx,
    },
    rpc::clementine::{
        clementine_operator_client::ClementineOperatorClient,
        clementine_verifier_client::ClementineVerifierClient, GrpcInputType,
        TransactionType as ProtoTransactionType,
    },
};
use clementine::*;
use clementine_errors::BridgeError;
use eyre::WrapErr;
use hyper_util::rt::TokioIo;
use std::{path::PathBuf, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri};
use tx::{
    assert_timeout::AssertTimeoutInput,
    burn_unused_kickoff_connectors::BurnUnusedKickoffConnectorsInput, challenge::ChallengeInput,
    challenge_timeout::ChallengeTimeoutInput, disprove::DisproveInput,
    disprove_timeout::DisproveTimeoutInput, emergency_stop::EmergencyStopInput,
    kickoff::KickoffInput, kickoff_not_finalized::KickoffNotFinalizedInput,
    latest_blockhash::LatestBlockhashInput, latest_blockhash_timeout::LatestBlockhashTimeoutInput,
    mini_assert::MiniAssertInput, move_to_vault::MoveToVaultInput,
    operator_challenge_ack::OperatorChallengeAckInput,
    operator_challenge_nack::OperatorChallengeNackInput, optimistic_payout::OptimisticPayoutInput,
    payout::PayoutInput, ready_to_reimburse::ReadyToReimburseInput, reimburse::ReimburseInput,
    replacement_deposit::ReplacementDepositInput, unspent_kickoff::UnspentKickoffInput,
    watchtower_challenge::WatchtowerChallengeInput,
    watchtower_challenge_timeout::WatchtowerChallengeTimeoutInput,
    yield_kickoff_txid::YieldKickoffTxidInput,
};

#[allow(clippy::all)]
#[rustfmt::skip]
pub mod clementine;

pub mod aggregator;
pub mod ecdsa_verification_sig;
mod error;
pub mod interceptors;
pub mod operator;
pub mod parser;
pub mod verifier;

pub use parser::ParserError;

fn input_variant_indices(input: &Input) -> Vec<u32> {
    match input {
        Input::BurnUnusedKickoffConnectors(
            crate::protocol::tx::burn_unused_kickoff_connectors::BurnUnusedKickoffConnectorsInput::UnusedKickoffConnector(idx),
        ) => vec![*idx as u32],
        _ => vec![],
    }
}

impl From<Input> for GrpcInputId {
    fn from(value: Input) -> Self {
        let input_type = match value {
            Input::Kickoff(tx::kickoff::KickoffInput::Round) => GrpcInputType::KickoffRound,
            Input::MoveToVault(tx::move_to_vault::MoveToVaultInput::DepositOutpoint) => {
                GrpcInputType::MoveToVaultDepositOutpoint
            }
            Input::EmergencyStop(tx::emergency_stop::EmergencyStopInput::DepositInMove) => {
                GrpcInputType::EmergencyStopDepositInMove
            }
            Input::YieldKickoffTxid(tx::yield_kickoff_txid::YieldKickoffTxidInput::Marker) => {
                GrpcInputType::YieldKickoffTxidMarker
            }
            Input::WatchtowerChallenge(tx::watchtower_challenge::WatchtowerChallengeInput::Kickoff) => {
                GrpcInputType::WatchtowerChallengeKickoff
            }
            Input::ReadyToReimburse(tx::ready_to_reimburse::ReadyToReimburseInput::CollateralInRound) => {
                GrpcInputType::ReadyToReimburseCollateralInRound
            }
            Input::UnspentKickoff(tx::unspent_kickoff::UnspentKickoffInput::CollateralInReadyToReimburse) => {
                GrpcInputType::UnspentKickoffCollateralInReadyToReimburse
            }
            Input::UnspentKickoff(tx::unspent_kickoff::UnspentKickoffInput::Kickoff) => {
                GrpcInputType::UnspentKickoffKickoff
            }
            Input::OperatorChallengeAck(tx::operator_challenge_ack::OperatorChallengeAckInput::WatchtowerChallengeAck) => {
                GrpcInputType::OperatorChallengeAckWatchtowerChallengeAck
            }
            Input::WatchtowerChallengeTimeout(
                tx::watchtower_challenge_timeout::WatchtowerChallengeTimeoutInput::WatchtowerChallenge,
            ) => {
                GrpcInputType::WatchtowerChallengeTimeoutWatchtowerChallenge
            }
            Input::WatchtowerChallengeTimeout(
                tx::watchtower_challenge_timeout::WatchtowerChallengeTimeoutInput::WatchtowerChallengeAck,
            ) => {
                GrpcInputType::WatchtowerChallengeTimeoutWatchtowerChallengeAck
            }
            Input::OperatorChallengeNack(tx::operator_challenge_nack::OperatorChallengeNackInput::WatchtowerChallengeAck) => {
                GrpcInputType::OperatorChallengeNackWatchtowerChallengeAck
            }
            Input::OperatorChallengeNack(tx::operator_challenge_nack::OperatorChallengeNackInput::KickoffFinalizer) => {
                GrpcInputType::OperatorChallengeNackKickoffFinalizer
            }
            Input::OperatorChallengeNack(tx::operator_challenge_nack::OperatorChallengeNackInput::CollateralInRound) => {
                GrpcInputType::OperatorChallengeNackCollateralInRound
            }
            Input::ChallengeTimeout(tx::challenge_timeout::ChallengeTimeoutInput::Challenge) => {
                GrpcInputType::ChallengeTimeoutChallenge
            }
            Input::ChallengeTimeout(tx::challenge_timeout::ChallengeTimeoutInput::KickoffFinalizer) => {
                GrpcInputType::ChallengeTimeoutKickoffFinalizer
            }
            Input::KickoffNotFinalized(tx::kickoff_not_finalized::KickoffNotFinalizedInput::KickoffFinalizer) => {
                GrpcInputType::KickoffNotFinalizedKickoffFinalizer
            }
            Input::KickoffNotFinalized(
                tx::kickoff_not_finalized::KickoffNotFinalizedInput::CollateralInReadyToReimburse,
            ) => {
                GrpcInputType::KickoffNotFinalizedCollateralInReadyToReimburse
            }
            Input::DisproveTimeout(tx::disprove_timeout::DisproveTimeoutInput::Disprove) => {
                GrpcInputType::DisproveTimeoutDisprove
            }
            Input::DisproveTimeout(tx::disprove_timeout::DisproveTimeoutInput::KickoffFinalizer) => {
                GrpcInputType::DisproveTimeoutKickoffFinalizer
            }
            Input::LatestBlockhashTimeout(tx::latest_blockhash_timeout::LatestBlockhashTimeoutInput::LatestBlockhash) => {
                GrpcInputType::LatestBlockhashTimeoutLatestBlockhash
            }
            Input::LatestBlockhashTimeout(tx::latest_blockhash_timeout::LatestBlockhashTimeoutInput::KickoffFinalizer) => {
                GrpcInputType::LatestBlockhashTimeoutKickoffFinalizer
            }
            Input::LatestBlockhashTimeout(tx::latest_blockhash_timeout::LatestBlockhashTimeoutInput::CollateralInRound) => {
                GrpcInputType::LatestBlockhashTimeoutCollateralInRound
            }
            Input::LatestBlockhash(tx::latest_blockhash::LatestBlockhashInput::LatestBlockhash) => {
                GrpcInputType::LatestBlockhashLatestBlockhash
            }
            Input::MiniAssert(tx::mini_assert::MiniAssertInput::Assert) => {
                GrpcInputType::MiniAssertAssert
            }
            Input::AssertTimeout(tx::assert_timeout::AssertTimeoutInput::Assert) => {
                GrpcInputType::AssertTimeoutAssert
            }
            Input::AssertTimeout(tx::assert_timeout::AssertTimeoutInput::KickoffFinalizer) => {
                GrpcInputType::AssertTimeoutKickoffFinalizer
            }
            Input::AssertTimeout(tx::assert_timeout::AssertTimeoutInput::CollateralInRound) => {
                GrpcInputType::AssertTimeoutCollateralInRound
            }
            Input::Disprove(tx::disprove::DisproveInput::Disprove) => GrpcInputType::DisproveDisprove,
            Input::Disprove(tx::disprove::DisproveInput::CollateralInRound) => {
                GrpcInputType::DisproveCollateralInRound
            }
            Input::Challenge(tx::challenge::ChallengeInput::Challenge) => {
                GrpcInputType::ChallengeChallenge
            }
            Input::Reimburse(tx::reimburse::ReimburseInput::DepositInMove) => {
                GrpcInputType::ReimburseDepositInMove
            }
            Input::Reimburse(tx::reimburse::ReimburseInput::ReimburseInKickoff) => {
                GrpcInputType::ReimburseReimburseInKickoff
            }
            Input::Reimburse(tx::reimburse::ReimburseInput::ReimburseInRound) => {
                GrpcInputType::ReimburseReimburseInRound
            }
            Input::Payout(tx::payout::PayoutInput::WithdrawalUtxo) => {
                GrpcInputType::PayoutWithdrawalUtxo
            }
            Input::OptimisticPayout(tx::optimistic_payout::OptimisticPayoutInput::WithdrawalUtxo) => {
                GrpcInputType::OptimisticPayoutWithdrawalUtxo
            }
            Input::OptimisticPayout(tx::optimistic_payout::OptimisticPayoutInput::DepositInMove) => {
                GrpcInputType::OptimisticPayoutDepositInMove
            }
            Input::ReplacementDeposit(tx::replacement_deposit::ReplacementDepositInput::ReplacementOutpoint) => {
                GrpcInputType::ReplacementDepositOutpoint
            }
            Input::BurnUnusedKickoffConnectors(_) => {
                GrpcInputType::BurnUnusedKickoffConnectorsUnusedKickoff
            }
        } as i32;

        Self {
            input_type,
            variant_indices: input_variant_indices(&value),
        }
    }
}

impl TryFrom<GrpcInputId> for Input {
    type Error = BridgeError;

    fn try_from(value: GrpcInputId) -> Result<Self, Self::Error> {
        let input_type = GrpcInputType::try_from(value.input_type)
            .map_err(|_| eyre::eyre!("unknown protocol input id"))?;
        Ok(match input_type {
            GrpcInputType::GrpcInputUnknown => {
                return Err(eyre::eyre!("unknown protocol input id").into())
            }
            GrpcInputType::KickoffRound => {
                zero_variant_input(value, input_type, KickoffInput::Round)?
            }
            GrpcInputType::MoveToVaultDepositOutpoint => {
                zero_variant_input(value, input_type, MoveToVaultInput::DepositOutpoint)?
            }
            GrpcInputType::EmergencyStopDepositInMove => {
                zero_variant_input(value, input_type, EmergencyStopInput::DepositInMove)?
            }
            GrpcInputType::YieldKickoffTxidMarker => {
                zero_variant_input(value, input_type, YieldKickoffTxidInput::Marker)?
            }
            GrpcInputType::WatchtowerChallengeKickoff => {
                zero_variant_input(value, input_type, WatchtowerChallengeInput::Kickoff)?
            }
            GrpcInputType::ReadyToReimburseCollateralInRound => {
                zero_variant_input(value, input_type, ReadyToReimburseInput::CollateralInRound)?
            }
            GrpcInputType::UnspentKickoffCollateralInReadyToReimburse => zero_variant_input(
                value,
                input_type,
                UnspentKickoffInput::CollateralInReadyToReimburse,
            )?,
            GrpcInputType::UnspentKickoffKickoff => {
                zero_variant_input(value, input_type, UnspentKickoffInput::Kickoff)?
            }
            GrpcInputType::OperatorChallengeAckWatchtowerChallengeAck => zero_variant_input(
                value,
                input_type,
                OperatorChallengeAckInput::WatchtowerChallengeAck,
            )?,
            GrpcInputType::WatchtowerChallengeTimeoutWatchtowerChallenge => zero_variant_input(
                value,
                input_type,
                WatchtowerChallengeTimeoutInput::WatchtowerChallenge,
            )?,
            GrpcInputType::WatchtowerChallengeTimeoutWatchtowerChallengeAck => zero_variant_input(
                value,
                input_type,
                WatchtowerChallengeTimeoutInput::WatchtowerChallengeAck,
            )?,
            GrpcInputType::OperatorChallengeNackWatchtowerChallengeAck => zero_variant_input(
                value,
                input_type,
                OperatorChallengeNackInput::WatchtowerChallengeAck,
            )?,
            GrpcInputType::OperatorChallengeNackKickoffFinalizer => zero_variant_input(
                value,
                input_type,
                OperatorChallengeNackInput::KickoffFinalizer,
            )?,
            GrpcInputType::OperatorChallengeNackCollateralInRound => zero_variant_input(
                value,
                input_type,
                OperatorChallengeNackInput::CollateralInRound,
            )?,
            GrpcInputType::ChallengeTimeoutChallenge => {
                zero_variant_input(value, input_type, ChallengeTimeoutInput::Challenge)?
            }
            GrpcInputType::ChallengeTimeoutKickoffFinalizer => {
                zero_variant_input(value, input_type, ChallengeTimeoutInput::KickoffFinalizer)?
            }
            GrpcInputType::KickoffNotFinalizedKickoffFinalizer => zero_variant_input(
                value,
                input_type,
                KickoffNotFinalizedInput::KickoffFinalizer,
            )?,
            GrpcInputType::KickoffNotFinalizedCollateralInReadyToReimburse => zero_variant_input(
                value,
                input_type,
                KickoffNotFinalizedInput::CollateralInReadyToReimburse,
            )?,
            GrpcInputType::DisproveTimeoutDisprove => {
                zero_variant_input(value, input_type, DisproveTimeoutInput::Disprove)?
            }
            GrpcInputType::DisproveTimeoutKickoffFinalizer => {
                zero_variant_input(value, input_type, DisproveTimeoutInput::KickoffFinalizer)?
            }
            GrpcInputType::LatestBlockhashTimeoutLatestBlockhash => zero_variant_input(
                value,
                input_type,
                LatestBlockhashTimeoutInput::LatestBlockhash,
            )?,
            GrpcInputType::LatestBlockhashTimeoutKickoffFinalizer => zero_variant_input(
                value,
                input_type,
                LatestBlockhashTimeoutInput::KickoffFinalizer,
            )?,
            GrpcInputType::LatestBlockhashTimeoutCollateralInRound => zero_variant_input(
                value,
                input_type,
                LatestBlockhashTimeoutInput::CollateralInRound,
            )?,
            GrpcInputType::LatestBlockhashLatestBlockhash => {
                zero_variant_input(value, input_type, LatestBlockhashInput::LatestBlockhash)?
            }
            GrpcInputType::MiniAssertAssert => {
                zero_variant_input(value, input_type, MiniAssertInput::Assert)?
            }
            GrpcInputType::AssertTimeoutAssert => {
                zero_variant_input(value, input_type, AssertTimeoutInput::Assert)?
            }
            GrpcInputType::AssertTimeoutKickoffFinalizer => {
                zero_variant_input(value, input_type, AssertTimeoutInput::KickoffFinalizer)?
            }
            GrpcInputType::AssertTimeoutCollateralInRound => {
                zero_variant_input(value, input_type, AssertTimeoutInput::CollateralInRound)?
            }
            GrpcInputType::DisproveDisprove => {
                zero_variant_input(value, input_type, DisproveInput::Disprove)?
            }
            GrpcInputType::DisproveCollateralInRound => {
                zero_variant_input(value, input_type, DisproveInput::CollateralInRound)?
            }
            GrpcInputType::ChallengeChallenge => {
                zero_variant_input(value, input_type, ChallengeInput::Challenge)?
            }
            GrpcInputType::ReimburseDepositInMove => {
                zero_variant_input(value, input_type, ReimburseInput::DepositInMove)?
            }
            GrpcInputType::ReimburseReimburseInKickoff => {
                zero_variant_input(value, input_type, ReimburseInput::ReimburseInKickoff)?
            }
            GrpcInputType::ReimburseReimburseInRound => {
                zero_variant_input(value, input_type, ReimburseInput::ReimburseInRound)?
            }
            GrpcInputType::PayoutWithdrawalUtxo => {
                zero_variant_input(value, input_type, PayoutInput::WithdrawalUtxo)?
            }
            GrpcInputType::OptimisticPayoutWithdrawalUtxo => {
                zero_variant_input(value, input_type, OptimisticPayoutInput::WithdrawalUtxo)?
            }
            GrpcInputType::OptimisticPayoutDepositInMove => {
                zero_variant_input(value, input_type, OptimisticPayoutInput::DepositInMove)?
            }
            GrpcInputType::ReplacementDepositOutpoint => zero_variant_input(
                value,
                input_type,
                ReplacementDepositInput::ReplacementOutpoint,
            )?,
            GrpcInputType::BurnUnusedKickoffConnectorsUnusedKickoff => {
                let idx = single_variant_input_index(value, input_type)?;
                BurnUnusedKickoffConnectorsInput::UnusedKickoffConnector(idx as usize).into()
            }
        })
    }
}

fn ensure_input_variant_indices(
    value: &GrpcInputId,
    input_type: GrpcInputType,
    expected_variant_len: usize,
) -> Result<(), BridgeError> {
    if value.variant_indices.len() != expected_variant_len {
        return Err(eyre::eyre!(
            "unexpected variant_indices {:?} for grpc input {:?}",
            value.variant_indices,
            input_type
        )
        .into());
    }
    Ok(())
}

fn zero_variant_input(
    value: GrpcInputId,
    input_type: GrpcInputType,
    input: impl Into<Input>,
) -> Result<Input, BridgeError> {
    ensure_input_variant_indices(&value, input_type, 0)?;
    Ok(input.into())
}

fn single_variant_input_index(
    value: GrpcInputId,
    input_type: GrpcInputType,
) -> Result<u32, BridgeError> {
    ensure_input_variant_indices(&value, input_type, 1)?;
    Ok(value.variant_indices[0])
}

impl From<TransactionType> for TransactionId {
    fn from(value: TransactionType) -> Self {
        let transaction_type = ProtoTransactionType::from(&value) as i32;

        match value {
            TransactionType::MoveToVault
            | TransactionType::EmergencyStop
            | TransactionType::Payout
            | TransactionType::OptimisticPayout
            | TransactionType::ReplacementDeposit
            | TransactionType::YieldKickoffTxid => Self {
                transaction_type,
                round_idx: 0,
                kickoff_idx: 0,
                variant_indices: vec![],
            },
            TransactionType::Round(round) | TransactionType::ReadyToReimburse(round) => Self {
                transaction_type,
                round_idx: round.0 as u32,
                kickoff_idx: 0,
                variant_indices: vec![],
            },
            TransactionType::Kickoff(round, kickoff)
            | TransactionType::Challenge(round, kickoff)
            | TransactionType::ChallengeTimeout(round, kickoff)
            | TransactionType::KickoffNotFinalized(round, kickoff)
            | TransactionType::LatestBlockhash(round, kickoff)
            | TransactionType::LatestBlockhashTimeout(round, kickoff)
            | TransactionType::Disprove(round, kickoff)
            | TransactionType::DisproveTimeout(round, kickoff)
            | TransactionType::Reimburse(round, kickoff) => Self {
                transaction_type,
                round_idx: round.0 as u32,
                kickoff_idx: kickoff.0 as u32,
                variant_indices: vec![],
            },
            TransactionType::WatchtowerChallenge(round, kickoff, _)
            | TransactionType::WatchtowerChallengeTimeout(round, kickoff, _)
            | TransactionType::OperatorChallengeNack(round, kickoff, _)
            | TransactionType::OperatorChallengeAck(round, kickoff, _)
            | TransactionType::MiniAssert(round, kickoff, _)
            | TransactionType::AssertTimeout(round, kickoff, _) => Self {
                transaction_type,
                round_idx: round.0 as u32,
                kickoff_idx: kickoff.0 as u32,
                variant_indices: vec![variant_index(&value)],
            },
            TransactionType::UnspentKickoff(round, kickoff) => Self {
                transaction_type,
                round_idx: round.0 as u32,
                kickoff_idx: kickoff.0 as u32,
                variant_indices: vec![],
            },
            TransactionType::BurnUnusedKickoffConnectors(round, indices) => Self {
                transaction_type,
                round_idx: round.0 as u32,
                kickoff_idx: 0,
                variant_indices: indices.into_iter().map(|idx| idx as u32).collect(),
            },
        }
    }
}

impl TryFrom<TransactionId> for TransactionType {
    type Error = BridgeError;

    fn try_from(value: TransactionId) -> Result<Self, Self::Error> {
        use ProtoTransactionType as ProtoTxType;

        let round = RoundIdx::new(value.round_idx as usize);
        let kickoff = KickoffIdx::new(value.kickoff_idx as usize);
        let tx_type =
            ProtoTxType::try_from(value.transaction_type).wrap_err("invalid transaction type")?;

        Ok(match tx_type {
            ProtoTxType::MoveToVault => without_indices(value, TransactionType::MoveToVault)?,
            ProtoTxType::EmergencyStop => without_indices(value, TransactionType::EmergencyStop)?,
            ProtoTxType::Payout => without_indices(value, TransactionType::Payout)?,
            ProtoTxType::OptimisticPayout => {
                without_indices(value, TransactionType::OptimisticPayout)?
            }
            ProtoTxType::ReplacementDeposit => {
                without_indices(value, TransactionType::ReplacementDeposit)?
            }
            ProtoTxType::YieldKickoffTxid => {
                without_indices(value, TransactionType::YieldKickoffTxid)?
            }
            ProtoTxType::Round => round_only(value, TransactionType::Round(round))?,
            ProtoTxType::ReadyToReimburse => {
                round_only(value, TransactionType::ReadyToReimburse(round))?
            }
            ProtoTxType::Kickoff => {
                round_kickoff_only(value, TransactionType::Kickoff(round, kickoff))?
            }
            ProtoTxType::Challenge => {
                round_kickoff_only(value, TransactionType::Challenge(round, kickoff))?
            }
            ProtoTxType::ChallengeTimeout => {
                round_kickoff_only(value, TransactionType::ChallengeTimeout(round, kickoff))?
            }
            ProtoTxType::KickoffNotFinalized => {
                round_kickoff_only(value, TransactionType::KickoffNotFinalized(round, kickoff))?
            }
            ProtoTxType::LatestBlockhash => {
                round_kickoff_only(value, TransactionType::LatestBlockhash(round, kickoff))?
            }
            ProtoTxType::LatestBlockhashTimeout => round_kickoff_only(
                value,
                TransactionType::LatestBlockhashTimeout(round, kickoff),
            )?,
            ProtoTxType::Disprove => {
                round_kickoff_only(value, TransactionType::Disprove(round, kickoff))?
            }
            ProtoTxType::DisproveTimeout => {
                round_kickoff_only(value, TransactionType::DisproveTimeout(round, kickoff))?
            }
            ProtoTxType::Reimburse => {
                round_kickoff_only(value, TransactionType::Reimburse(round, kickoff))?
            }
            ProtoTxType::WatchtowerChallenge => round_kickoff_with_variant(value, |idx| {
                TransactionType::WatchtowerChallenge(round, kickoff, idx)
            })?,
            ProtoTxType::WatchtowerChallengeTimeout => round_kickoff_with_variant(value, |idx| {
                TransactionType::WatchtowerChallengeTimeout(round, kickoff, idx)
            })?,
            ProtoTxType::OperatorChallengeNack => round_kickoff_with_variant(value, |idx| {
                TransactionType::OperatorChallengeNack(round, kickoff, idx)
            })?,
            ProtoTxType::OperatorChallengeAck => round_kickoff_with_variant(value, |idx| {
                TransactionType::OperatorChallengeAck(round, kickoff, idx)
            })?,
            ProtoTxType::MiniAssert => round_kickoff_with_variant(value, |idx| {
                TransactionType::MiniAssert(round, kickoff, idx)
            })?,
            ProtoTxType::AssertTimeout => round_kickoff_with_variant(value, |idx| {
                TransactionType::AssertTimeout(round, kickoff, idx)
            })?,
            ProtoTxType::UnspentKickoff => {
                round_kickoff_only(value, TransactionType::UnspentKickoff(round, kickoff))?
            }
            ProtoTxType::BurnUnusedKickoffConnectors => burn_unused_kickoff(value, round)?,
            ProtoTxType::UnspecifiedTransactionType => {
                return Err(eyre::eyre!("missing transaction type").into())
            }
        })
    }
}

impl From<&TransactionType> for ProtoTransactionType {
    fn from(value: &TransactionType) -> Self {
        match value {
            TransactionType::MoveToVault => Self::MoveToVault,
            TransactionType::EmergencyStop => Self::EmergencyStop,
            TransactionType::Round(_) => Self::Round,
            TransactionType::ReadyToReimburse(_) => Self::ReadyToReimburse,
            TransactionType::Kickoff(_, _) => Self::Kickoff,
            TransactionType::Challenge(_, _) => Self::Challenge,
            TransactionType::ChallengeTimeout(_, _) => Self::ChallengeTimeout,
            TransactionType::KickoffNotFinalized(_, _) => Self::KickoffNotFinalized,
            TransactionType::WatchtowerChallenge(_, _, _) => Self::WatchtowerChallenge,
            TransactionType::WatchtowerChallengeTimeout(_, _, _) => {
                Self::WatchtowerChallengeTimeout
            }
            TransactionType::OperatorChallengeNack(_, _, _) => Self::OperatorChallengeNack,
            TransactionType::OperatorChallengeAck(_, _, _) => Self::OperatorChallengeAck,
            TransactionType::LatestBlockhash(_, _) => Self::LatestBlockhash,
            TransactionType::LatestBlockhashTimeout(_, _) => Self::LatestBlockhashTimeout,
            TransactionType::MiniAssert(_, _, _) => Self::MiniAssert,
            TransactionType::AssertTimeout(_, _, _) => Self::AssertTimeout,
            TransactionType::Disprove(_, _) => Self::Disprove,
            TransactionType::DisproveTimeout(_, _) => Self::DisproveTimeout,
            TransactionType::UnspentKickoff(_, _) => Self::UnspentKickoff,
            TransactionType::BurnUnusedKickoffConnectors(_, _) => Self::BurnUnusedKickoffConnectors,
            TransactionType::Reimburse(_, _) => Self::Reimburse,
            TransactionType::Payout => Self::Payout,
            TransactionType::OptimisticPayout => Self::OptimisticPayout,
            TransactionType::ReplacementDeposit => Self::ReplacementDeposit,
            TransactionType::YieldKickoffTxid => Self::YieldKickoffTxid,
        }
    }
}

fn variant_index(tx_type: &TransactionType) -> u32 {
    let index = match tx_type {
        TransactionType::WatchtowerChallenge(_, _, idx)
        | TransactionType::WatchtowerChallengeTimeout(_, _, idx)
        | TransactionType::OperatorChallengeNack(_, _, idx)
        | TransactionType::OperatorChallengeAck(_, _, idx)
        | TransactionType::MiniAssert(_, _, idx)
        | TransactionType::AssertTimeout(_, _, idx) => *idx,
        _ => unreachable!("variant_index called for non-variant transaction type"),
    };
    index as u32
}

fn ensure_indices(
    value: &TransactionId,
    expected_kickoff_idx: u32,
    expected_variant_len: usize,
) -> Result<(), BridgeError> {
    if value.kickoff_idx != expected_kickoff_idx {
        return Err(eyre::eyre!(
            "unexpected kickoff_idx {} for transaction {:?}",
            value.kickoff_idx,
            value.transaction_type
        )
        .into());
    }
    if value.variant_indices.len() != expected_variant_len {
        return Err(eyre::eyre!(
            "unexpected variant_indices {:?} for transaction {:?}",
            value.variant_indices,
            value.transaction_type
        )
        .into());
    }
    Ok(())
}

fn without_indices(
    value: TransactionId,
    tx_type: TransactionType,
) -> Result<TransactionType, BridgeError> {
    if value.round_idx != 0 {
        return Err(eyre::eyre!(
            "unexpected round_idx {} for transaction {:?}",
            value.round_idx,
            value.transaction_type
        )
        .into());
    }
    ensure_indices(&value, 0, 0)?;
    Ok(tx_type)
}

fn round_only(
    value: TransactionId,
    tx_type: TransactionType,
) -> Result<TransactionType, BridgeError> {
    ensure_indices(&value, 0, 0)?;
    Ok(tx_type)
}

fn round_kickoff_only(
    value: TransactionId,
    tx_type: TransactionType,
) -> Result<TransactionType, BridgeError> {
    ensure_indices(&value, value.kickoff_idx, 0)?;
    Ok(tx_type)
}

fn round_kickoff_with_variant<F>(
    value: TransactionId,
    tx_type: F,
) -> Result<TransactionType, BridgeError>
where
    F: FnOnce(usize) -> TransactionType,
{
    ensure_indices(&value, value.kickoff_idx, 1)?;
    Ok(tx_type(value.variant_indices[0] as usize))
}

fn burn_unused_kickoff(
    value: TransactionId,
    round: RoundIdx,
) -> Result<TransactionType, BridgeError> {
    if value.kickoff_idx != 0 {
        return Err(eyre::eyre!(
            "unexpected kickoff_idx {} for transaction {:?}",
            value.kickoff_idx,
            value.transaction_type
        )
        .into());
    }
    Ok(TransactionType::BurnUnusedKickoffConnectors(
        round,
        value
            .variant_indices
            .into_iter()
            .map(|idx| idx as usize)
            .collect(),
    ))
}

/// Returns gRPC clients.
///
/// # Parameters
///
/// - `endpoints`: URIs for clients (can be http/https URLs or unix:// paths)
/// - `connect`: Function that will be used to initiate gRPC connection
/// - `config`: Configuration containing TLS certificate paths
///
/// # Returns
///
/// - `CLIENT`: [`tonic`] gRPC client.
pub async fn get_clients<CLIENT, F>(
    endpoints: Vec<String>,
    connect: F,
    config: &crate::config::BridgeConfig,
    use_client_cert: bool,
) -> Result<Vec<CLIENT>, BridgeError>
where
    F: Fn(Channel) -> CLIENT,
{
    // Ensure certificates exist in test mode
    #[cfg(test)]
    {
        crate::test::common::ensure_test_certificates().map_err(|e| {
            BridgeError::ConfigError(format!("Failed to ensure test certificates: {e}"))
        })?;
    }

    // Get certificate paths from config or use defaults
    let client_ca_cert = tokio::fs::read(&config.ca_cert_path)
        .await
        .wrap_err(format!(
            "Failed to read CA certificate from {}",
            config.ca_cert_path.display()
        ))?;

    let client_ca = Certificate::from_pem(client_ca_cert);

    // Get certificate paths from config or use defaults
    let client_cert_path = &config.client_cert_path.clone();
    let client_key_path = &config.client_key_path.clone();

    // Load client certificate and key
    let client_cert = tokio::fs::read(&client_cert_path).await.map_err(|e| {
        BridgeError::ConfigError(format!(
            "Failed to read client certificate from {}: {}",
            client_cert_path.display(),
            e
        ))
    })?;

    let client_key = tokio::fs::read(&client_key_path).await.map_err(|e| {
        BridgeError::ConfigError(format!(
            "Failed to read client key from {}: {}",
            client_key_path.display(),
            e
        ))
    })?;

    futures::future::try_join_all(
        endpoints
            .into_iter()
            .map(|endpoint| {
                let client_cert = client_cert.clone();
                let client_key = client_key.clone();
                let client_ca = client_ca.clone();

                let tls_config = if use_client_cert {
                    let client_identity = Identity::from_pem(client_cert, client_key);
                    ClientTlsConfig::new()
                        .identity(client_identity)
                        .ca_certificate(client_ca)
                } else {
                    ClientTlsConfig::new().ca_certificate(client_ca)
                };

                let connect = &connect;

                async move {
                    let channel = if endpoint.starts_with("unix://") {
                        #[cfg(unix)]
                        {
                            // Handle Unix socket (only available on Unix platforms)
                            let path = endpoint.trim_start_matches("unix://").to_string();
                            Channel::from_static("lttp://[::]:50051")
                                .connect_with_connector(tower::service_fn(move |_| {
                                    let path = PathBuf::from(path.clone());
                                    async move {
                                        let unix_stream =
                                            tokio::net::UnixStream::connect(path).await?;
                                        Ok::<_, std::io::Error>(TokioIo::new(unix_stream))
                                    }
                                }))
                                .await
                                .wrap_err_with(|| {
                                    format!("Failed to connect to Unix socket {endpoint}")
                                })?
                        }

                        #[cfg(not(unix))]
                        {
                            // Windows doesn't support Unix sockets
                            return Err(BridgeError::ConfigError(format!(
                                "Unix sockets ({}), are not supported on this platform",
                                endpoint
                            )));
                        }
                    } else {
                        // Handle TCP/HTTP connection
                        let uri = Uri::try_from(endpoint.clone()).map_err(|e| {
                            BridgeError::ConfigError(format!(
                                "Endpoint {endpoint} is malformed: {e}"
                            ))
                        })?;

                        Channel::builder(uri)
                            .timeout(Duration::from_secs(config.grpc.timeout_secs))
                            .concurrency_limit(config.grpc.req_concurrency_limit)
                            .keep_alive_timeout(Duration::from_secs(config.grpc.tcp_keepalive_secs))
                            .tls_config(tls_config)
                            .wrap_err("Failed to configure TLS")?
                            .connect_lazy()
                    };

                    Ok(connect(channel))
                }
            })
            .collect::<Vec<_>>(),
    )
    .await
}

pub fn operator_client_builder(
    config: &BridgeConfig,
) -> impl Fn(Channel) -> ClementineOperatorClient<Channel> {
    let max_msg_size = config.grpc.max_message_size;
    move |channel| {
        ClementineOperatorClient::new(channel)
            .max_decoding_message_size(max_msg_size)
            .max_encoding_message_size(max_msg_size)
    }
}

pub fn verifier_client_builder(
    config: &BridgeConfig,
) -> impl Fn(Channel) -> ClementineVerifierClient<Channel> {
    let max_msg_size = config.grpc.max_message_size;
    move |channel| {
        ClementineVerifierClient::new(channel)
            .max_decoding_message_size(max_msg_size)
            .max_encoding_message_size(max_msg_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_input_id_rejects_unexpected_variant_indices_on_non_variant_input() {
        let err = Input::try_from(GrpcInputId {
            input_type: GrpcInputType::PayoutWithdrawalUtxo as i32,
            variant_indices: vec![7],
        })
        .expect_err("non-variant inputs must reject unexpected variant indices");

        assert!(err.to_string().contains("unexpected variant_indices"));
    }

    #[test]
    fn grpc_input_id_rejects_non_canonical_burn_unused_indices() {
        let missing = Input::try_from(GrpcInputId {
            input_type: GrpcInputType::BurnUnusedKickoffConnectorsUnusedKickoff as i32,
            variant_indices: vec![],
        })
        .expect_err("burn-unused input requires exactly one variant index");
        assert!(missing.to_string().contains("unexpected variant_indices"));

        let extra = Input::try_from(GrpcInputId {
            input_type: GrpcInputType::BurnUnusedKickoffConnectorsUnusedKickoff as i32,
            variant_indices: vec![1, 2],
        })
        .expect_err("burn-unused input must reject extra variant indices");
        assert!(extra.to_string().contains("unexpected variant_indices"));
    }

    #[test]
    fn grpc_input_id_roundtrips_canonical_burn_unused_index() {
        let input = BurnUnusedKickoffConnectorsInput::UnusedKickoffConnector(5).into();
        let decoded = Input::try_from(GrpcInputId::from(input)).expect("canonical grpc id");
        assert_eq!(decoded, input);
    }
}
