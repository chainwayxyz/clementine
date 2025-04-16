use statig::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::{
    builder::transaction::{ContractContext, OperatorData, TransactionType},
    errors::{BridgeError, TxError},
};
use bitcoin::OutPoint;
use serde_with::serde_as;

use super::{
    block_cache::BlockCache,
    context::{Duty, StateContext},
    matcher::{self, BlockMatcher},
    Owner, StateMachineError,
};

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum RoundEvent {
    KickoffUtxoUsed {
        kickoff_idx: usize,
        kickoff_outpoint: OutPoint,
    },
    ReadyToReimburseSent {
        round_idx: u32,
    },
    RoundSent {
        round_idx: u32,
    },
    /// Special event that is used to indicate that the state machine has been saved to the database and the dirty flag should be reset
    SavedToDb,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoundStateMachine<T: Owner> {
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) matchers: HashMap<matcher::Matcher, RoundEvent>,
    pub(crate) operator_data: OperatorData,
    pub(crate) dirty: bool,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Owner> BlockMatcher for RoundStateMachine<T> {
    type StateEvent = RoundEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::StateEvent> {
        self.matchers
            .iter()
            .filter_map(|(matcher, round_event)| {
                matcher.matches(block).map(|ord| (ord, round_event))
            })
            .min()
            .map(|(_, round_event)| round_event)
            .into_iter()
            .cloned()
            .collect()
    }
}

impl<T: Owner> RoundStateMachine<T> {
    pub fn new(operator_data: OperatorData) -> Self {
        Self {
            matchers: HashMap::new(),
            operator_data,
            dirty: true,
            phantom: std::marker::PhantomData,
        }
    }
}
use eyre::Context;

#[state_machine(
    initial = "State::initial_collateral()",
    on_dispatch = "Self::on_dispatch",
    on_transition = "Self::on_transition",
    state(derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize))
)]
impl<T: Owner> RoundStateMachine<T> {
    #[action]
    pub(crate) fn on_transition(&mut self, state_a: &State, state_b: &State) {
        tracing::trace!(?self.operator_data, "Transitioning from {:?} to {:?}", state_a, state_b);
        self.dirty = true;
    }

    pub fn round_meta(&self, method: &'static str) -> StateMachineError {
        eyre::eyre!(
            "Error in round state machine for operator {} in {}",
            self.operator_data.xonly_pk,
            method
        )
        .into()
    }

    async fn unhandled_event(&mut self, context: &mut StateContext<T>, event: &RoundEvent) {
        context
            .capture_error(async |_context| {
                let event_str = format!("{:?}", event);
                Err(StateMachineError::UnhandledEvent(event_str))
                    .wrap_err(self.round_meta("round unhandled event"))
            })
            .await;
    }

    #[action]
    pub(crate) fn on_dispatch(
        &mut self,
        _state: StateOrSuperstate<'_, '_, Self>,
        evt: &RoundEvent,
    ) {
        if matches!(evt, RoundEvent::SavedToDb) {
            self.dirty = false;
        } else {
            tracing::debug!(?self.operator_data, "Dispatching event {:?}", evt);
            self.dirty = true;

            // Remove the matcher corresponding to the event.
            if let Some((matcher, _)) = self.matchers.iter().find(|(_, ev)| ev == &evt) {
                let matcher = matcher.clone();
                self.matchers.remove(&matcher);
            }
        }
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
            RoundEvent::SavedToDb => Handled,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    #[action]
    #[allow(unused_variables)]
    pub(crate) async fn on_initial_collateral_entry(&mut self, context: &mut StateContext<T>) {
        self.matchers = HashMap::new();
        self.matchers.insert(
            matcher::Matcher::SpentUtxo(self.operator_data.collateral_funding_outpoint),
            RoundEvent::RoundSent { round_idx: 0 },
        );
    }

    #[state(entry_action = "on_round_tx_entry", exit_action = "on_round_tx_exit")]
    #[allow(unused_variables)]
    pub(crate) async fn round_tx(
        &mut self,
        event: &RoundEvent,
        round_idx: &mut u32,
        used_kickoffs: &mut HashSet<usize>,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            RoundEvent::KickoffUtxoUsed {
                kickoff_idx,
                kickoff_outpoint,
            } => {
                used_kickoffs.insert(*kickoff_idx);
                let txid = context
                    .cache
                    .get_txid_of_utxo(kickoff_outpoint)
                    .expect("UTXO should be in block");

                context
                    .capture_error(async |context| {
                        context
                            .owner
                            .handle_duty(Duty::CheckIfKickoff {
                                txid,
                                block_height: context.cache.block_height,
                                witness: context
                                    .cache
                                    .get_witness_of_utxo(kickoff_outpoint)
                                    .expect("UTXO should be in block"),
                            })
                            .await?;
                        Ok(())
                    })
                    .await;
                Handled
            }
            RoundEvent::ReadyToReimburseSent { round_idx } => {
                Transition(State::ready_to_reimburse(*round_idx))
            }
            RoundEvent::SavedToDb => Handled,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
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
                            operator_xonly_pk: self.operator_data.xonly_pk,
                        })
                        .await?;
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.round_meta("on_round_tx_exit"))
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
                        self.operator_data.xonly_pk,
                        *round_idx,
                        context.paramset,
                    );
                    let mut txhandlers = context
                        .owner
                        .create_txhandlers(TransactionType::Round, contract_context)
                        .await?;
                    let round_txhandler = txhandlers
                        .remove(&TransactionType::Round)
                        .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?;
                    let ready_to_reimburse_txhandler = txhandlers
                        .remove(&TransactionType::ReadyToReimburse)
                        .ok_or(TxError::TxHandlerNotFound(
                            TransactionType::ReadyToReimburse,
                        ))?;
                    self.matchers.insert(
                        matcher::Matcher::SentTx(*ready_to_reimburse_txhandler.get_txid()),
                        RoundEvent::ReadyToReimburseSent {
                            round_idx: *round_idx,
                        },
                    );
                    for idx in 0..context.paramset.num_kickoffs_per_round {
                        let outpoint = *round_txhandler
                            .get_spendable_output(idx + 1)?
                            .get_prev_outpoint();
                        self.matchers.insert(
                            matcher::Matcher::SpentUtxo(outpoint),
                            RoundEvent::KickoffUtxoUsed {
                                kickoff_idx: idx,
                                kickoff_outpoint: outpoint,
                            },
                        );
                    }
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.round_meta("on_round_tx_entry"))
            })
            .await;
    }

    #[state(entry_action = "on_ready_to_reimburse_entry")]
    #[allow(unused_variables)]
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
            RoundEvent::SavedToDb => Handled,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
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
                        self.operator_data.xonly_pk,
                        *round_idx + 1,
                        context.paramset,
                    );
                    let next_round_txhandlers = context
                        .owner
                        .create_txhandlers(TransactionType::Round, contract_context)
                        .await?;
                    let next_round_txid = next_round_txhandlers
                        .get(&TransactionType::Round)
                        .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?
                        .get_txid();
                    self.matchers.insert(
                        matcher::Matcher::SentTx(*next_round_txid),
                        RoundEvent::RoundSent {
                            round_idx: *round_idx + 1,
                        },
                    );
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.round_meta("on_ready_to_reimburse_entry"))
            })
            .await;
    }
}
