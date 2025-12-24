use statig::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::builder::transaction::{input::UtxoVout, ContractContext};
use crate::deposit::OperatorData;
use bitcoin::OutPoint;
use clementine_errors::BridgeError;
use clementine_errors::TxError;
use clementine_primitives::RoundIndex;
use clementine_primitives::TransactionType;
use serde_with::serde_as;

use super::{
    block_cache::BlockCache,
    context::{Duty, DutyResult, StateContext},
    matcher::{self, BlockMatcher},
    Owner, StateMachineError,
};

/// Events that change the state of the round state machine.
#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum RoundEvent {
    /// Event that is dispatched when a kickoff utxo in a round tx is spent.
    KickoffUtxoUsed {
        kickoff_idx: usize,
        kickoff_outpoint: OutPoint,
    },
    /// Event that is dispatched when the next ready to reimburse tx is mined.
    ReadyToReimburseSent { round_idx: RoundIndex },
    /// Event that is dispatched when the next round tx is mined.
    RoundSent { round_idx: RoundIndex },
    /// This event is sent if operators collateral was spent in any way other than default behaviour (default is round -> ready to reimburse -> round -> ready to reimburse -> ...)
    /// It means operator stopped participating in the protocol and can no longer participate in clementine bridge protocol.
    OperatorExit,
    /// Special event that is used to indicate that the state machine has been saved to the database and the dirty flag should be reset to false
    SavedToDb,
}

/// State machine for the round state.
/// It has following states:
///     - `initial_collateral`: The initial collateral state, when the operator didn't create the first round tx yet.
///     - `round_tx`: The round tx state, when the operator's collateral utxo is currently in a round tx.
///     - `ready_to_reimburse`: The ready to reimburse state, when the operator's collateral utxo is currently in a ready to reimburse tx.
///     - `operator_exit`: The operator exit state, when the operator exited the protocol (collateral spent in a non-bridge tx).
///
/// It has following events:
/// - `KickoffUtxoUsed`: The kickoff utxo is used in a round tx. The state machine stores this utxo as used, and additionally calls the owner to check if this kickoff utxo was used in a kickoff tx (If so, that will result in creation of a kickoff state machine).
/// - `ReadyToReimburseSent`: The ready to reimburse tx is sent. The state machine transitions to the ready to reimburse state. Additionally, if there are unused kickoff utxos, this information is passed to the owner which can then create a "Unspent Kickoff Connector" tx.
/// - `RoundSent`: The round tx is sent. The state machine transitions to the round tx state.
/// - `OperatorExit`: The operator exited the protocol. The state machine transitions to the operator exit state. In this state, all tracking of the operator is stopped as operator is no longer participating in the protocol.
/// - `SavedToDb`: The state machine has been saved to the database and the dirty flag should be reset to false.
///
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoundStateMachine<T: Owner> {
    /// Maps matchers to the resulting round events.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) matchers: HashMap<matcher::Matcher, RoundEvent>,
    /// Data of the operator that is being tracked.
    pub(crate) operator_data: OperatorData,
    /// Indicates if the state machine has unsaved changes that need to be persisted on db.
    /// dirty flag is set if any matcher matches the current block.
    /// the flag is set to true in on_transition and on_dispatch
    /// the flag is set to false after the state machine is saved to db and the event SavedToDb is dispatched
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
                let event_str = format!("{event:?}");
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
            tracing::trace!(?self.operator_data, "Dispatching event {:?}", evt);
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
            // If the initial collateral is spent, we can transition to the first round tx.
            RoundEvent::RoundSent { round_idx } => {
                Transition(State::round_tx(*round_idx, HashSet::new(), false))
            }
            RoundEvent::SavedToDb => Handled,
            RoundEvent::OperatorExit => Transition(State::operator_exit()),
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    /// Entry action for the initial collateral state.
    /// This method adds the matcher for the first round tx and the matcher if the operator exits
    /// the protocol by not spending the collateral in the first round tx.
    #[action]
    #[allow(unused_variables)]
    pub(crate) async fn on_initial_collateral_entry(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    self.matchers = HashMap::new();

                    // To determine if operator exited the protocol, we check if collateral was not spent in the first round tx.
                    let contract_context = ContractContext::new_context_for_round(
                        self.operator_data.xonly_pk,
                        RoundIndex::Round(0),
                        context.config.protocol_paramset,
                    );

                    let mut guard = context.shared_dbtx.lock().await;
                    let round_txhandlers = context
                        .owner
                        .create_txhandlers(&mut guard, TransactionType::Round, contract_context)
                        .await?;
                    drop(guard);
                    let round_txid = round_txhandlers
                        .get(&TransactionType::Round)
                        .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?
                        .get_txid();
                    // if round tx is sent, we can send the round sent event
                    self.matchers.insert(
                        matcher::Matcher::SentTx(*round_txid),
                        RoundEvent::RoundSent {
                            round_idx: RoundIndex::Round(0),
                        },
                    );
                    // If the tx the collateral is spent on is not the round tx, we dispatch the operator exit event.
                    self.matchers.insert(
                        matcher::Matcher::SpentUtxoButNotTxid(
                            self.operator_data.collateral_funding_outpoint,
                            vec![*round_txid],
                        ),
                        RoundEvent::OperatorExit,
                    );
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.round_meta("on_initial_collateral_entry"))
            })
            .await;
    }

    /// State that represents a round tx.
    /// This state is entered when a round tx is mined.
    /// It is exited when the operator sends the ready to reimburse tx or exits the protocol.
    #[state(entry_action = "on_round_tx_entry", exit_action = "on_round_tx_exit")]
    #[allow(unused_variables)]
    pub(crate) async fn round_tx(
        &mut self,
        event: &RoundEvent,
        round_idx: &mut RoundIndex,
        used_kickoffs: &mut HashSet<usize>,
        challenged_before: &mut bool,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            // If a kickoff utxo is spent, we add it to the used kickoffs set.
            // The set will be used to determine if the operator has used all kickoffs in the round.
            // If the operator did not use all kickoffs, "Unspent Kickoff Connector" tx can potentially be sent, slashing the operator.
            // Additionally, the owner will check if the kickoff utxo is used in a kickoff transaction.
            // If so, the owner (if verifier) will do additional checks to determine if the kickoff is malicious or not.
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
                        {
                            let duty_result = context
                                .dispatch_duty(Duty::CheckIfKickoff {
                                    txid,
                                    block_height: context.cache.block_height,
                                    witness: context
                                        .cache
                                        .get_witness_of_utxo(kickoff_outpoint)
                                        .expect("UTXO should be in block"),
                                    challenged_before: *challenged_before,
                                })
                                .await?;
                            if let DutyResult::CheckIfKickoff { challenged } = duty_result {
                                *challenged_before |= challenged;
                            }
                            Ok::<(), BridgeError>(())
                        }
                        .wrap_err(self.round_meta("round_tx kickoff_utxo_used"))
                    })
                    .await;
                Handled
            }
            // If the ready to reimburse tx is mined, we transition to the ready to reimburse state.
            RoundEvent::ReadyToReimburseSent { round_idx } => {
                Transition(State::ready_to_reimburse(*round_idx))
            }
            RoundEvent::SavedToDb => Handled,
            RoundEvent::OperatorExit => Transition(State::operator_exit()),
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    /// State that represents the operator exiting the protocol.
    #[state(entry_action = "on_operator_exit_entry")]
    pub(crate) async fn operator_exit(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            RoundEvent::SavedToDb => Handled,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    /// Entry action for the operator exit state.
    /// This method removes all matchers for the round state machine.
    /// We do not care about anything after the operator exits the protocol.
    /// For example, even if operator sends a kickoff after exiting the protocol, that
    /// kickoff is useless as reimburse connector utxo of that kickoff is in the next round,
    /// which cannot be created anymore as the collateral is spent. So we do not want to challenge it, etc.
    #[action]
    pub(crate) async fn on_operator_exit_entry(&mut self) {
        self.matchers = HashMap::new();
        tracing::warn!(?self.operator_data, "Operator exited the protocol.");
    }

    /// Exit action for the round tx state.
    /// This method will check if all kickoffs were used in the round.
    /// If not, the owner will send a "Unspent Kickoff Connector" tx, slashing the operator.
    #[action]
    pub(crate) async fn on_round_tx_exit(
        &mut self,
        round_idx: &mut RoundIndex,
        used_kickoffs: &mut HashSet<usize>,
        context: &mut StateContext<T>,
    ) {
        context
            .capture_error(async |context| {
                {
                    context
                        .dispatch_duty(Duty::NewReadyToReimburse {
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

    /// Entry action for the round tx state.
    /// This method adds the matchers for the round tx and the ready to reimburse tx.
    /// It adds the matchers for the kickoff utxos in the round tx.
    /// It also adds the matchers for the operator exit.
    #[action]
    pub(crate) async fn on_round_tx_entry(
        &mut self,
        round_idx: &mut RoundIndex,
        challenged_before: &mut bool,
        context: &mut StateContext<T>,
    ) {
        // ensure challenged_before starts at false for each round
        // In a single round, a challenge is enough to slash all of the operators current kickoffs in the same round.
        // This way, if the operator posts 50 different kickoffs, we only need one challenge.
        // If that challenge is successful, operator will not be able to get reimbursement from all kickoffs.
        *challenged_before = false;
        context
            .capture_error(async |context| {
                {
                    self.matchers = HashMap::new();
                    // On the round after last round, do not care about anything,
                    // last round has index num_round_txs and is there only for reimbursement generators of previous round
                    // nothing is signed with them
                    if *round_idx
                        == RoundIndex::Round(context.config.protocol_paramset.num_round_txs)
                    {
                        Ok::<(), BridgeError>(())
                    } else {
                        let contract_context = ContractContext::new_context_for_round(
                            self.operator_data.xonly_pk,
                            *round_idx,
                            context.config.protocol_paramset,
                        );

                        let mut guard = context.shared_dbtx.lock().await;
                        let mut txhandlers = context
                            .owner
                            .create_txhandlers(&mut guard, TransactionType::Round, contract_context)
                            .await?;
                        drop(guard);

                        let round_txhandler = txhandlers
                            .remove(&TransactionType::Round)
                            .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?;
                        let ready_to_reimburse_txhandler = txhandlers
                            .remove(&TransactionType::ReadyToReimburse)
                            .ok_or(TxError::TxHandlerNotFound(
                                TransactionType::ReadyToReimburse,
                            ))?;
                        // Add a matcher for the ready to reimburse tx.
                        self.matchers.insert(
                            matcher::Matcher::SentTx(*ready_to_reimburse_txhandler.get_txid()),
                            RoundEvent::ReadyToReimburseSent {
                                round_idx: *round_idx,
                            },
                        );
                        // To determine if operator exited the protocol, we check if collateral was not spent in ready to reimburse tx.
                        self.matchers.insert(
                            matcher::Matcher::SpentUtxoButNotTxid(
                                OutPoint::new(
                                    *round_txhandler.get_txid(),
                                    UtxoVout::CollateralInRound.get_vout(),
                                ),
                                vec![*ready_to_reimburse_txhandler.get_txid()],
                            ),
                            RoundEvent::OperatorExit,
                        );
                        // Add a matcher for each kickoff utxo in the round tx.
                        for idx in 0..context.config.protocol_paramset.num_kickoffs_per_round {
                            let outpoint = *round_txhandler
                                .get_spendable_output(UtxoVout::Kickoff(idx))?
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
        round_idx: &mut RoundIndex,
    ) -> Response<State> {
        match event {
            // If the next round tx is mined, we transition to the round tx state.
            RoundEvent::RoundSent {
                round_idx: next_round_idx,
            } => Transition(State::round_tx(*next_round_idx, HashSet::new(), false)),
            RoundEvent::SavedToDb => Handled,
            RoundEvent::OperatorExit => Transition(State::operator_exit()),
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    /// Entry action for the ready to reimburse state.
    /// This method adds the matchers for the next round tx and the operator exit.
    #[action]
    pub(crate) async fn on_ready_to_reimburse_entry(
        &mut self,
        context: &mut StateContext<T>,
        round_idx: &mut RoundIndex,
    ) {
        context
            .capture_error(async |context| {
                {
                    self.matchers = HashMap::new();
                    // get next rounds Round tx
                    let next_round_context = ContractContext::new_context_for_round(
                        self.operator_data.xonly_pk,
                        round_idx.next_round(),
                        context.config.protocol_paramset,
                    );

                    let mut guard = context.shared_dbtx.lock().await;
                    let next_round_txhandlers = context
                        .owner
                        .create_txhandlers(&mut guard, TransactionType::Round, next_round_context)
                        .await?;
                    drop(guard);

                    let next_round_txid = next_round_txhandlers
                        .get(&TransactionType::Round)
                        .ok_or(TxError::TxHandlerNotFound(TransactionType::Round))?
                        .get_txid();
                    // Add a matcher for the next round tx.
                    self.matchers.insert(
                        matcher::Matcher::SentTx(*next_round_txid),
                        RoundEvent::RoundSent {
                            round_idx: round_idx.next_round(),
                        },
                    );
                    // calculate the current ready to reimburse txid
                    // to generate the SpentUtxoButNotTxid matcher for the operator exit
                    let current_round_context = ContractContext::new_context_for_round(
                        self.operator_data.xonly_pk,
                        *round_idx,
                        context.config.protocol_paramset,
                    );

                    let mut guard = context.shared_dbtx.lock().await;
                    let current_round_txhandlers = context
                        .owner
                        .create_txhandlers(
                            &mut guard,
                            TransactionType::Round,
                            current_round_context,
                        )
                        .await?;
                    drop(guard);

                    let current_ready_to_reimburse_txid = current_round_txhandlers
                        .get(&TransactionType::ReadyToReimburse)
                        .ok_or(TxError::TxHandlerNotFound(
                            TransactionType::ReadyToReimburse,
                        ))?
                        .get_txid();

                    // To determine if operator exited the protocol, we check if collateral was not spent in the next round tx.
                    self.matchers.insert(
                        matcher::Matcher::SpentUtxoButNotTxid(
                            OutPoint::new(
                                *current_ready_to_reimburse_txid,
                                UtxoVout::CollateralInReadyToReimburse.get_vout(),
                            ),
                            vec![*next_round_txid],
                        ),
                        RoundEvent::OperatorExit,
                    );
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.round_meta("on_ready_to_reimburse_entry"))
            })
            .await;
    }
}
