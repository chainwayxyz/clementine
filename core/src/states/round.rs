use eyre::Context;
use statig::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::{
    builder::transaction::{ContractContext, OperatorData, TransactionType},
    errors::BridgeError,
    states::Duty,
};

use super::{BlockCache, BlockMatcher, Matcher, Owner, StateContext};

#[derive(Debug, Clone)]
pub enum RoundEvent {
    KickoffUtxoUsed { kickoff_idx: usize },
    ReadyToReimburseSent { round_idx: u32 },
    RoundSent { round_idx: u32 },
}

#[derive(Debug, Clone)]
pub struct RoundStateMachine<T: Owner> {
    pub(crate) matchers: HashMap<Matcher, RoundEvent>,
    operator_data: OperatorData,
    operator_idx: u32,
    pub(crate) dirty: bool,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Owner> BlockMatcher for RoundStateMachine<T> {
    type StateEvent = RoundEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::StateEvent> {
        self.matchers
            .iter()
            .filter_map(|(matcher, round_event)| {
                if matcher.matches(block) {
                    Some(round_event.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<T: Owner> RoundStateMachine<T> {
    pub fn new(operator_data: OperatorData, operator_idx: u32) -> Self {
        Self {
            matchers: HashMap::new(),
            operator_data,
            operator_idx,
            dirty: false,
            phantom: std::marker::PhantomData,
        }
    }
}
use eyre::Report;

#[state_machine(
    initial = "State::initial_collateral()",
    on_transition = "Self::on_transition",
    state(derive(Debug, Clone))
)]
// TODO: Add exit conditions too (ex: burn connector spent on smth else)
impl<T: Owner> RoundStateMachine<T> {
    pub fn wrap_err(
        &'_ self,
        method: &'static str,
    ) -> impl FnOnce(BridgeError) -> eyre::Report + '_ {
        move |e| {
            Report::from(e).wrap_err(format!(
                "Error in round state machine for operator {} in {}",
                self.operator_idx, method
            ))
        }
    }

    #[action]
    pub(crate) fn on_transition(&mut self, state_a: &State, state_b: &State) {
        tracing::debug!(?self.operator_data, ?self.operator_idx, "Transitioning from {:?} to {:?}", state_a, state_b);
        self.dirty = true;
    }

    #[state(entry_action = "on_initial_collateral_entry")]
    pub(crate) async fn initial_collateral(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            RoundEvent::RoundSent { round_idx } => {
                Transition(State::round_tx(*round_idx, HashSet::new()))
            }
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_initial_collateral_entry(&mut self, context: &mut StateContext<T>) {
        self.matchers = HashMap::new();
        self.matchers.insert(
            Matcher::SpentUtxo(self.operator_data.collateral_funding_outpoint),
            RoundEvent::RoundSent { round_idx: 0 },
        );
    }

    #[state(entry_action = "on_round_tx_entry", exit_action = "on_round_tx_exit")]
    pub(crate) async fn round_tx(
        &mut self,
        event: &RoundEvent,
        round_idx: &mut u32,
        used_kickoffs: &mut HashSet<usize>,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            RoundEvent::KickoffUtxoUsed { kickoff_idx } => {
                used_kickoffs.insert(*kickoff_idx);
                Handled
            }
            RoundEvent::ReadyToReimburseSent { round_idx } => {
                Transition(State::ready_to_reimburse(*round_idx))
            }
            _ => Handled,
        }
    }

    #[action]
    pub(crate) async fn on_round_tx_exit(
        &mut self,
        round_idx: &mut u32,
        used_kickoffs: &mut HashSet<usize>,
        context: &mut StateContext<T>,
    ) {
        context
            .capture_error(async |context| {
                {
                    context
                        .owner
                        .handle_duty(Duty::NewReadyToReimburse {
                            round_idx: *round_idx,
                            used_kickoffs: used_kickoffs.clone(),
                            operator_idx: self.operator_idx,
                        })
                        .await?;
                    Ok(())
                }
                .map_err(self.wrap_err("on_round_tx_exit"))
            })
            .await;
    }

    #[action]
    pub(crate) async fn on_round_tx_entry(
        &mut self,
        round_idx: &mut u32,
        context: &mut StateContext<T>,
    ) {
        context
            .capture_error(async |context| {
                {
                    self.matchers = HashMap::new();
                    let contract_context = ContractContext::new_context_for_rounds(
                        self.operator_idx,
                        *round_idx,
                        context.paramset,
                    );
                    let mut txhandlers = context
                        .owner
                        .create_txhandlers(TransactionType::Round, contract_context)
                        .await?;
                    let round_txhandler = txhandlers
                        .remove(&TransactionType::Round)
                        .ok_or(BridgeError::TxHandlerNotFound(TransactionType::Round))?;
                    let ready_to_reimburse_txhandler = txhandlers
                        .remove(&TransactionType::ReadyToReimburse)
                        .ok_or(BridgeError::TxHandlerNotFound(
                            TransactionType::ReadyToReimburse,
                        ))?;
                    self.matchers.insert(
                        Matcher::SentTx(*ready_to_reimburse_txhandler.get_txid()),
                        RoundEvent::ReadyToReimburseSent {
                            round_idx: *round_idx,
                        },
                    );
                    for idx in 1..context.paramset.num_kickoffs_per_round + 1 {
                        self.matchers.insert(
                            Matcher::SpentUtxo(
                                *round_txhandler
                                    .get_spendable_output(idx)?
                                    .get_prev_outpoint(),
                            ),
                            RoundEvent::KickoffUtxoUsed { kickoff_idx: idx },
                        );
                    }
                    Ok(())
                }
                .map_err(self.wrap_err("on_round_tx_entry"))
            })
            .await;
    }

    #[state(entry_action = "on_ready_to_reimburse_entry")]
    pub(crate) async fn ready_to_reimburse(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
        round_idx: &mut u32,
    ) -> Response<State> {
        match event {
            RoundEvent::RoundSent { round_idx } => {
                Transition(State::round_tx(*round_idx, HashSet::new()))
            }
            _ => Handled,
        }
    }

    #[action]
    pub(crate) async fn on_ready_to_reimburse_entry(
        &mut self,
        context: &mut StateContext<T>,
        round_idx: &mut u32,
    ) {
        context
            .capture_error(async |context| {
                {
                    self.matchers = HashMap::new();
                    // get next rounds Round tx
                    let contract_context = ContractContext::new_context_for_rounds(
                        self.operator_idx,
                        *round_idx + 1,
                        context.paramset,
                    );
                    let next_round_txhandlers = context
                        .owner
                        .create_txhandlers(TransactionType::Round, contract_context)
                        .await?;
                    let next_round_txid = next_round_txhandlers
                        .get(&TransactionType::Round)
                        .ok_or(BridgeError::TxHandlerNotFound(TransactionType::Round))?
                        .get_txid();
                    self.matchers.insert(
                        Matcher::SentTx(*next_round_txid),
                        RoundEvent::RoundSent {
                            round_idx: *round_idx + 1,
                        },
                    );
                    Ok(())
                }
                .map_err(self.wrap_err("on_ready_to_reimburse_entry"))
            })
            .await;
    }
}
