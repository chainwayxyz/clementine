use std::collections::{BTreeMap, HashSet};

use crate::bitvm_client::ClementineBitVMPublicKeys;
use crate::builder::transaction::{
    BuildContextView, KickoffBuildContext, RoundBuildContext, SpendableTxIn, TxCache, TxCacheExt,
    TxHandler, TxHandlerBuilder, UnspentTxOut,
};
use crate::protocol::ids::{Input, Output, TransactionType};
use crate::protocol::spec::{ExternalInput, InputSource, InputSpec, TxSpec};
use crate::protocol::tx;
use bitcoin::Address;
use clementine_errors::BridgeError;
use eyre::eyre;

#[derive(Debug, Clone)]
pub enum BatchName {
    Tx(TransactionType),
    Txs(Vec<TransactionType>),
    RoundChain {
        round: crate::protocol::ids::RoundIdx,
    },
    UnspentKickoffs {
        round: crate::protocol::ids::RoundIdx,
    },
    KickoffMonitoring {
        round: crate::protocol::ids::RoundIdx,
        kickoff: crate::protocol::ids::KickoffIdx,
    },
    MiniAsserts {
        round: crate::protocol::ids::RoundIdx,
        kickoff: crate::protocol::ids::KickoffIdx,
    },
    OperatorPostDepositSignable {
        round: crate::protocol::ids::RoundIdx,
        kickoff: crate::protocol::ids::KickoffIdx,
    },
    VerifierPostDepositSignable {
        round: crate::protocol::ids::RoundIdx,
        kickoff: crate::protocol::ids::KickoffIdx,
    },
    OperatorDepositRequested {
        round: crate::protocol::ids::RoundIdx,
        kickoff: crate::protocol::ids::KickoffIdx,
    },
    VerifierDepositRequested {
        round: crate::protocol::ids::RoundIdx,
        kickoff: crate::protocol::ids::KickoffIdx,
    },
}

pub fn build_batch<C>(ctx: &mut C, batch_name: &BatchName) -> Result<TxCache, BridgeError>
where
    C: BuildContextView,
{
    let mut cache = TxCache::new();
    build_batch_cached(ctx, batch_name, &mut cache)
}

pub fn build_tx<C>(ctx: &mut C, tx_type: TransactionType) -> Result<TxHandler, BridgeError>
where
    C: BuildContextView,
{
    let mut cache = build_batch(ctx, &BatchName::Tx(tx_type.clone()))?;
    cache.take_required(tx_type)
}

pub fn build_batch_cached<C>(
    ctx: &mut C,
    batch_name: &BatchName,
    cache: &mut TxCache,
) -> Result<TxCache, BridgeError>
where
    C: BuildContextView,
{
    let requested = resolve_batch(batch_name, ctx)?;
    let mut visiting = HashSet::new();

    for tx_type in &requested {
        get_or_create_tx(ctx, tx_type.clone(), cache, &mut visiting)?;
    }

    let mut requested_only = BTreeMap::new();
    for tx_type in requested {
        let txhandler = cache.get_required(tx_type.clone())?.clone();
        requested_only.insert(tx_type, txhandler);
    }

    Ok(requested_only)
}

pub fn build_watchtower_challenge(
    ctx: &mut KickoffBuildContext,
    tx_type: TransactionType,
    commit_data: Vec<u8>,
) -> Result<TxHandler, BridgeError> {
    let mut wrapped = WatchtowerChallengeContext {
        kickoff: ctx,
        commit_data,
    };
    build_tx(&mut wrapped, tx_type)
}

pub fn build_burn_unused_kickoff_connectors(
    ctx: &mut RoundBuildContext,
    tx_type: TransactionType,
    change_address: Address,
) -> Result<TxHandler, BridgeError> {
    let mut wrapped = BurnUnusedKickoffConnectorsContext {
        round: ctx,
        change_address,
    };
    build_tx(&mut wrapped, tx_type)
}

pub(crate) fn materialize_external_input<C>(
    tx_type: &TransactionType,
    external: &ExternalInput,
    ctx: &mut C,
) -> Result<SpendableTxIn, BridgeError>
where
    C: BuildContextView,
{
    match (tx_type, external) {
        (TransactionType::Round(_), ExternalInput::OperatorCollateral) => {
            tx::round::external_collateral_input(ctx)
        }
        (TransactionType::MoveToVault, ExternalInput::DepositOutpoint) => {
            tx::move_to_vault::materialize_deposit_input(ctx)
        }
        (TransactionType::ReplacementDeposit, ExternalInput::DepositOutpoint) => {
            tx::replacement_deposit::materialize_replacement_input(ctx)
        }
        (TransactionType::Payout, ExternalInput::WithdrawalUtxo)
        | (TransactionType::OptimisticPayout, ExternalInput::WithdrawalUtxo) => {
            tx::payout::materialize_withdrawal_input(ctx)
        }
        _ => unreachable!("unsupported external input {external:?} for tx type {tx_type:?}"),
    }
}

pub(crate) fn resolve_batch<C>(
    batch_name: &BatchName,
    ctx: &C,
) -> Result<Vec<TransactionType>, BridgeError>
where
    C: BuildContextView,
{
    use crate::protocol::ids::KickoffIdx;

    let num_watchtowers =
        || -> Result<usize, BridgeError> { Ok(ctx.deposit()?.get_num_watchtowers()) };
    let num_kickoffs = || ctx.params().num_kickoffs_per_round;
    let num_assert_txs = || ClementineBitVMPublicKeys::number_of_assert_txs();

    Ok(match batch_name {
        BatchName::Tx(tx_type) => vec![tx_type.clone()],
        BatchName::Txs(tx_types) => tx_types.clone(),
        BatchName::RoundChain { round } => vec![
            TransactionType::Round(*round),
            TransactionType::ReadyToReimburse(*round),
        ],
        BatchName::UnspentKickoffs { round } => (0..num_kickoffs())
            .map(|idx| TransactionType::UnspentKickoff(*round, KickoffIdx::new(idx)))
            .collect(),
        BatchName::KickoffMonitoring { round, kickoff } => {
            let mut requested = resolve_batch(
                &BatchName::VerifierDepositRequested {
                    round: *round,
                    kickoff: *kickoff,
                },
                ctx,
            )?;
            requested.push(TransactionType::Kickoff(*round, *kickoff));
            requested.push(TransactionType::Round(*round));
            requested
        }
        BatchName::MiniAsserts { round, kickoff } => (0..num_assert_txs())
            .map(|idx| TransactionType::MiniAssert(*round, *kickoff, idx))
            .collect(),
        BatchName::VerifierPostDepositSignable { round, kickoff } => {
            let mut requested = vec![
                TransactionType::Challenge(*round, *kickoff),
                TransactionType::KickoffNotFinalized(*round, *kickoff),
                TransactionType::LatestBlockhashTimeout(*round, *kickoff),
            ];
            requested.extend(
                (0..num_kickoffs())
                    .map(|idx| TransactionType::UnspentKickoff(*round, KickoffIdx::new(idx))),
            );
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::WatchtowerChallengeTimeout(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::OperatorChallengeNack(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_assert_txs())
                    .map(|idx| TransactionType::AssertTimeout(*round, *kickoff, idx)),
            );
            requested
        }
        BatchName::OperatorPostDepositSignable { round, kickoff } => {
            let mut requested = vec![
                TransactionType::Round(*round),
                TransactionType::ReadyToReimburse(*round),
                TransactionType::Kickoff(*round, *kickoff),
                TransactionType::KickoffNotFinalized(*round, *kickoff),
                TransactionType::Challenge(*round, *kickoff),
                TransactionType::DisproveTimeout(*round, *kickoff),
                TransactionType::Reimburse(*round, *kickoff),
                TransactionType::ChallengeTimeout(*round, *kickoff),
                TransactionType::LatestBlockhashTimeout(*round, *kickoff),
            ];
            requested.extend(
                (0..num_kickoffs())
                    .map(|idx| TransactionType::UnspentKickoff(*round, KickoffIdx::new(idx))),
            );
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::OperatorChallengeNack(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::OperatorChallengeAck(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_assert_txs())
                    .map(|idx| TransactionType::AssertTimeout(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::WatchtowerChallengeTimeout(*round, *kickoff, idx)),
            );
            requested
        }
        BatchName::VerifierDepositRequested { round, kickoff } => {
            let mut requested = vec![
                TransactionType::Reimburse(*round, *kickoff),
                TransactionType::ChallengeTimeout(*round, *kickoff),
                TransactionType::KickoffNotFinalized(*round, *kickoff),
                TransactionType::LatestBlockhashTimeout(*round, *kickoff),
                TransactionType::DisproveTimeout(*round, *kickoff),
            ];
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::WatchtowerChallengeTimeout(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::OperatorChallengeNack(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_assert_txs())
                    .map(|idx| TransactionType::AssertTimeout(*round, *kickoff, idx)),
            );
            requested
        }
        BatchName::OperatorDepositRequested { round, kickoff } => {
            let mut requested = vec![
                TransactionType::Challenge(*round, *kickoff),
                TransactionType::KickoffNotFinalized(*round, *kickoff),
                TransactionType::Disprove(*round, *kickoff),
                TransactionType::LatestBlockhashTimeout(*round, *kickoff),
            ];
            requested.extend(
                (0..num_watchtowers()?)
                    .map(|idx| TransactionType::OperatorChallengeNack(*round, *kickoff, idx)),
            );
            requested.extend(
                (0..num_assert_txs())
                    .map(|idx| TransactionType::AssertTimeout(*round, *kickoff, idx)),
            );
            requested
        }
    })
}

fn create_from_spec<C, I, O, Ri, Mo>(
    ctx: &mut C,
    tx_type: TransactionType,
    spec: TxSpec<I, O>,
    cache: &mut TxCache,
    visiting: &mut HashSet<TransactionType>,
    resolve_input: Ri,
    materialize_output: Mo,
) -> Result<TxHandler, BridgeError>
where
    C: BuildContextView,
    I: Copy + Into<Input>,
    O: Copy + Into<Output>,
    Ri: Fn(&I, &TransactionType, &C) -> Result<InputSpec, BridgeError>,
    Mo: Fn(&O, &TransactionType, &mut C, &TxCache) -> Result<UnspentTxOut, BridgeError>,
{
    let mut builder = TxHandlerBuilder::new(tx_type.clone())
        .with_version(spec.version)
        .with_lock_time(spec.lock_time);

    for input in &spec.inputs {
        let input_spec = resolve_input(input, &tx_type, ctx)?;
        let spendable = match &input_spec.source {
            InputSource::ParentOutput {
                tx_type: parent_tx_type,
                vout,
            } => {
                get_or_create_tx(ctx, parent_tx_type.clone(), cache, visiting)?;
                let parent = cache.get_required(parent_tx_type.clone())?;
                parent.get_spendable_output(*vout)?
            }
            InputSource::External(external) => materialize_external_input(&tx_type, external, ctx)?,
        };

        builder = builder.add_input(
            (*input).into(),
            spendable,
            input_spec.sequence,
            input_spec.spend,
        );
    }

    for output in &spec.outputs {
        let materialized = materialize_output(output, &tx_type, ctx, cache)?;
        builder = builder.add_output((*output).into(), materialized);
    }

    Ok(builder.finalize())
}

fn build_txhandler_with_visiting<C>(
    ctx: &mut C,
    tx_type: TransactionType,
    cache: &mut TxCache,
    visiting: &mut HashSet<TransactionType>,
) -> Result<TxHandler, BridgeError>
where
    C: BuildContextView,
{
    match tx_type.clone() {
        TransactionType::Round(_) => create_from_spec(
            ctx,
            tx_type,
            tx::round::spec(ctx.params().num_kickoffs_per_round),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::BurnUnusedKickoffConnectors(_, indices) => create_from_spec(
            ctx,
            tx_type,
            tx::burn_unused_kickoff_connectors::spec(&indices, ctx),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::Kickoff(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::kickoff::spec(
                ClementineBitVMPublicKeys::number_of_assert_txs(),
                ctx.deposit()?.get_num_watchtowers(),
            ),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| {
                Ok(output
                    .materialize(tx_type, ctx, cache)?
                    .expect("kickoff outputs are always present in the realized spec"))
            },
        ),
        TransactionType::MoveToVault => create_from_spec(
            ctx,
            tx_type,
            tx::move_to_vault::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::EmergencyStop => create_from_spec(
            ctx,
            tx_type,
            tx::emergency_stop::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::ReadyToReimburse(_) => create_from_spec(
            ctx,
            tx_type,
            tx::ready_to_reimburse::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::UnspentKickoff(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::unspent_kickoff::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::OperatorChallengeAck(_, _, _) => create_from_spec(
            ctx,
            tx_type,
            tx::operator_challenge_ack::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::OperatorChallengeNack(_, _, _) => create_from_spec(
            ctx,
            tx_type,
            tx::operator_challenge_nack::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::ChallengeTimeout(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::challenge_timeout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::KickoffNotFinalized(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::kickoff_not_finalized::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::DisproveTimeout(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::disprove_timeout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::Disprove(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::disprove::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::LatestBlockhashTimeout(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::latest_blockhash_timeout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::LatestBlockhash(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::latest_blockhash::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::MiniAssert(_, _, _) => create_from_spec(
            ctx,
            tx_type,
            tx::mini_assert::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::AssertTimeout(_, _, _) => create_from_spec(
            ctx,
            tx_type,
            tx::assert_timeout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::Challenge(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::challenge::spec(ctx),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::WatchtowerChallengeTimeout(_, _, _) => create_from_spec(
            ctx,
            tx_type,
            tx::watchtower_challenge_timeout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::WatchtowerChallenge(_, _, _) => create_from_spec(
            ctx,
            tx_type,
            tx::watchtower_challenge::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::YieldKickoffTxid => create_from_spec(
            ctx,
            tx_type,
            tx::yield_kickoff_txid::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::Payout => create_from_spec(
            ctx,
            tx_type,
            tx::payout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::OptimisticPayout => create_from_spec(
            ctx,
            tx_type,
            tx::optimistic_payout::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::ReplacementDeposit => create_from_spec(
            ctx,
            tx_type,
            tx::replacement_deposit::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
        TransactionType::Reimburse(_, _) => create_from_spec(
            ctx,
            tx_type,
            tx::reimburse::spec(),
            cache,
            visiting,
            |input, tx_type, ctx| Ok(input.resolve(tx_type, ctx)),
            |output, tx_type, ctx, cache| output.materialize(tx_type, ctx, cache),
        ),
    }
}

fn get_or_create_tx<C>(
    ctx: &mut C,
    tx_type: TransactionType,
    cache: &mut TxCache,
    visiting: &mut HashSet<TransactionType>,
) -> Result<(), BridgeError>
where
    C: BuildContextView,
{
    if cache.contains_key(&tx_type) {
        return Ok(());
    }

    if !visiting.insert(tx_type.clone()) {
        return Err(eyre!(
            "Cycle detected while resolving transaction dependencies for {tx_type:?}"
        )
        .into());
    }

    let result = (|| {
        let handler = build_txhandler_with_visiting(ctx, tx_type.clone(), cache, visiting)?;
        cache.insert(tx_type.clone(), handler);
        Ok(())
    })();

    visiting.remove(&tx_type);
    result
}

struct WatchtowerChallengeContext<'a> {
    kickoff: &'a mut KickoffBuildContext,
    commit_data: Vec<u8>,
}

impl BuildContextView for WatchtowerChallengeContext<'_> {
    fn params(&self) -> &'static crate::config::protocol::ProtocolParamset {
        self.kickoff.params()
    }

    fn deposit(&self) -> Result<&crate::deposit::DepositData, BridgeError> {
        self.kickoff.deposit()
    }

    fn deposit_mut(&mut self) -> Result<&mut crate::deposit::DepositData, BridgeError> {
        self.kickoff.deposit_mut()
    }

    fn operator(&self) -> Result<&crate::deposit::OperatorData, BridgeError> {
        self.kickoff.operator()
    }

    fn round_idx(&self) -> Result<clementine_primitives::BridgeRound, BridgeError> {
        self.kickoff.round_idx()
    }

    fn kickoff_data(&self) -> Result<crate::deposit::KickoffData, BridgeError> {
        self.kickoff.kickoff_data()
    }

    fn kickoff(&self) -> Result<&KickoffBuildContext, BridgeError> {
        self.kickoff.kickoff()
    }

    fn kickoff_keys(
        &self,
    ) -> Result<&crate::builder::transaction::KickoffWinternitzKeys, BridgeError> {
        Ok(self.kickoff.kickoff_keys())
    }

    fn move_to_vault_txid(&self) -> Result<bitcoin::Txid, BridgeError> {
        self.kickoff.move_to_vault_txid()
    }

    fn challenger_evm_address(
        &self,
    ) -> Result<Option<clementine_primitives::EVMAddress>, BridgeError> {
        Ok(self.kickoff.challenger_evm_address())
    }

    fn watchtower_commit_data(&self) -> Result<&[u8], BridgeError> {
        Ok(&self.commit_data)
    }
}

struct BurnUnusedKickoffConnectorsContext<'a> {
    round: &'a mut RoundBuildContext,
    change_address: Address,
}

impl BuildContextView for BurnUnusedKickoffConnectorsContext<'_> {
    fn params(&self) -> &'static crate::config::protocol::ProtocolParamset {
        self.round.params()
    }

    fn operator(&self) -> Result<&crate::deposit::OperatorData, BridgeError> {
        self.round.operator()
    }

    fn round_idx(&self) -> Result<clementine_primitives::BridgeRound, BridgeError> {
        self.round.round_idx()
    }

    fn kickoff_keys(
        &self,
    ) -> Result<&crate::builder::transaction::KickoffWinternitzKeys, BridgeError> {
        self.round.kickoff_keys()
    }

    fn burn_change_address(&self) -> Result<&Address, BridgeError> {
        Ok(&self.change_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::transaction::TxHandlerBuilder;
    use crate::config::protocol::{ProtocolParamset, REGTEST_PARAMSET};

    struct EmptyContext;

    impl BuildContextView for EmptyContext {
        fn params(&self) -> &'static ProtocolParamset {
            &REGTEST_PARAMSET
        }
    }

    #[test]
    fn build_batch_cached_reuses_cached_transactions() {
        let tx_type = TransactionType::MoveToVault;
        let mut cache = TxCache::new();
        cache.insert(
            tx_type.clone(),
            TxHandlerBuilder::new(tx_type.clone()).finalize(),
        );
        cache.insert(
            TransactionType::Payout,
            TxHandlerBuilder::new(TransactionType::Payout).finalize(),
        );

        let requested = build_batch_cached(
            &mut EmptyContext,
            &BatchName::Tx(tx_type.clone()),
            &mut cache,
        )
        .expect("cached tx should be returned without rebuilding");

        assert_eq!(requested.len(), 1);
        assert!(requested.contains_key(&tx_type));
        assert_eq!(cache.len(), 2);
    }
}
