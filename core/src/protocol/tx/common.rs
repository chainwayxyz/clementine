use crate::builder::transaction::{
    anchor_output, non_ephemeral_anchor_output, DataSources, UnspentTxOut,
};
use crate::protocol::ids::{KickoffIdx, RoundIdx, TransactionType};

pub(crate) fn anchor_output_utxo(datasources: &impl DataSources) -> UnspentTxOut {
    UnspentTxOut::from_partial(anchor_output(datasources.params().anchor_amount()))
}

pub(crate) fn non_ephemeral_anchor_output_utxo() -> UnspentTxOut {
    UnspentTxOut::from_partial(non_ephemeral_anchor_output())
}

pub(crate) fn round_kickoff_from(tx_type: &TransactionType) -> (RoundIdx, KickoffIdx) {
    match tx_type {
        TransactionType::Kickoff(round, kickoff)
        | TransactionType::Challenge(round, kickoff)
        | TransactionType::ChallengeTimeout(round, kickoff)
        | TransactionType::KickoffNotFinalized(round, kickoff)
        | TransactionType::LatestBlockhash(round, kickoff)
        | TransactionType::LatestBlockhashTimeout(round, kickoff)
        | TransactionType::Disprove(round, kickoff)
        | TransactionType::DisproveTimeout(round, kickoff)
        | TransactionType::UnspentKickoff(round, kickoff)
        | TransactionType::Reimburse(round, kickoff) => (*round, *kickoff),
        _ => unreachable!("round_kickoff_from used with wrong tx_type: {tx_type:?}"),
    }
}

pub(crate) fn round_kickoff_watchtower_from(
    tx_type: &TransactionType,
) -> (RoundIdx, KickoffIdx, usize) {
    match tx_type {
        TransactionType::WatchtowerChallenge(round, kickoff, watchtower_idx)
        | TransactionType::WatchtowerChallengeTimeout(round, kickoff, watchtower_idx)
        | TransactionType::OperatorChallengeAck(round, kickoff, watchtower_idx)
        | TransactionType::OperatorChallengeNack(round, kickoff, watchtower_idx) => {
            (*round, *kickoff, *watchtower_idx)
        }
        _ => unreachable!("round_kickoff_watchtower_from used with wrong tx_type: {tx_type:?}"),
    }
}

pub(crate) fn round_kickoff_assert_from(
    tx_type: &TransactionType,
) -> (RoundIdx, KickoffIdx, usize) {
    match tx_type {
        TransactionType::MiniAssert(round, kickoff, assert_idx)
        | TransactionType::AssertTimeout(round, kickoff, assert_idx) => {
            (*round, *kickoff, *assert_idx)
        }
        _ => unreachable!("round_kickoff_assert_from used with wrong tx_type: {tx_type:?}"),
    }
}
