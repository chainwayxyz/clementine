pub use clementine_primitives::{KickoffIdx, RoundIdx, TransactionType};

use crate::deposit::DepositTreeLeaf;
use crate::protocol::tx;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Actor {
    Operator,
    Verifier,
    Watchtower,
    SecurityCouncil,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Leaf {
    MoveToVault(tx::move_to_vault::MoveToVaultLeaf),
    EmergencyStop(tx::emergency_stop::EmergencyStopLeaf),
    Round(tx::round::RoundLeaf),
    Kickoff(tx::kickoff::KickoffLeaf),
    External(DepositTreeLeaf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    MoveToVault(tx::move_to_vault::MoveToVaultInput),
    EmergencyStop(tx::emergency_stop::EmergencyStopInput),
    ReadyToReimburse(tx::ready_to_reimburse::ReadyToReimburseInput),
    Kickoff(tx::kickoff::KickoffInput),
    Challenge(tx::challenge::ChallengeInput),
    ChallengeTimeout(tx::challenge_timeout::ChallengeTimeoutInput),
    KickoffNotFinalized(tx::kickoff_not_finalized::KickoffNotFinalizedInput),
    WatchtowerChallenge(tx::watchtower_challenge::WatchtowerChallengeInput),
    WatchtowerChallengeTimeout(tx::watchtower_challenge_timeout::WatchtowerChallengeTimeoutInput),
    OperatorChallengeNack(tx::operator_challenge_nack::OperatorChallengeNackInput),
    OperatorChallengeAck(tx::operator_challenge_ack::OperatorChallengeAckInput),
    LatestBlockhash(tx::latest_blockhash::LatestBlockhashInput),
    LatestBlockhashTimeout(tx::latest_blockhash_timeout::LatestBlockhashTimeoutInput),
    MiniAssert(tx::mini_assert::MiniAssertInput),
    AssertTimeout(tx::assert_timeout::AssertTimeoutInput),
    Disprove(tx::disprove::DisproveInput),
    DisproveTimeout(tx::disprove_timeout::DisproveTimeoutInput),
    UnspentKickoff(tx::unspent_kickoff::UnspentKickoffInput),
    BurnUnusedKickoffConnectors(
        tx::burn_unused_kickoff_connectors::BurnUnusedKickoffConnectorsInput,
    ),
    Reimburse(tx::reimburse::ReimburseInput),
    Payout(tx::payout::PayoutInput),
    OptimisticPayout(tx::optimistic_payout::OptimisticPayoutInput),
    ReplacementDeposit(tx::replacement_deposit::ReplacementDepositInput),
    YieldKickoffTxid(tx::yield_kickoff_txid::YieldKickoffTxidInput),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Output {
    MoveToVault(tx::move_to_vault::MoveToVaultOutput),
    EmergencyStop(tx::emergency_stop::EmergencyStopOutput),
    Round(tx::round::RoundOutput),
    ReadyToReimburse(tx::ready_to_reimburse::ReadyToReimburseOutput),
    Kickoff(tx::kickoff::KickoffOutput),
    Challenge(tx::challenge::ChallengeOutput),
    ChallengeTimeout(tx::challenge_timeout::ChallengeTimeoutOutput),
    KickoffNotFinalized(tx::kickoff_not_finalized::KickoffNotFinalizedOutput),
    WatchtowerChallenge(tx::watchtower_challenge::WatchtowerChallengeOutput),
    WatchtowerChallengeTimeout(tx::watchtower_challenge_timeout::WatchtowerChallengeTimeoutOutput),
    OperatorChallengeNack(tx::operator_challenge_nack::OperatorChallengeNackOutput),
    OperatorChallengeAck(tx::operator_challenge_ack::OperatorChallengeAckOutput),
    LatestBlockhash(tx::latest_blockhash::LatestBlockhashOutput),
    LatestBlockhashTimeout(tx::latest_blockhash_timeout::LatestBlockhashTimeoutOutput),
    MiniAssert(tx::mini_assert::MiniAssertOutput),
    AssertTimeout(tx::assert_timeout::AssertTimeoutOutput),
    Disprove(tx::disprove::DisproveOutput),
    DisproveTimeout(tx::disprove_timeout::DisproveTimeoutOutput),
    UnspentKickoff(tx::unspent_kickoff::UnspentKickoffOutput),
    BurnUnusedKickoffConnectors(
        tx::burn_unused_kickoff_connectors::BurnUnusedKickoffConnectorsOutput,
    ),
    Reimburse(tx::reimburse::ReimburseOutput),
    Payout(tx::payout::PayoutOutput),
    OptimisticPayout(tx::optimistic_payout::OptimisticPayoutOutput),
    ReplacementDeposit(tx::replacement_deposit::ReplacementDepositOutput),
}

impl From<tx::move_to_vault::MoveToVaultLeaf> for Leaf {
    fn from(value: tx::move_to_vault::MoveToVaultLeaf) -> Self {
        Self::MoveToVault(value)
    }
}

impl From<tx::emergency_stop::EmergencyStopLeaf> for Leaf {
    fn from(value: tx::emergency_stop::EmergencyStopLeaf) -> Self {
        Self::EmergencyStop(value)
    }
}

impl From<tx::round::RoundLeaf> for Leaf {
    fn from(value: tx::round::RoundLeaf) -> Self {
        Self::Round(value)
    }
}

impl From<tx::kickoff::KickoffLeaf> for Leaf {
    fn from(value: tx::kickoff::KickoffLeaf) -> Self {
        Self::Kickoff(value)
    }
}

impl From<DepositTreeLeaf> for Leaf {
    fn from(value: DepositTreeLeaf) -> Self {
        Self::External(value)
    }
}
