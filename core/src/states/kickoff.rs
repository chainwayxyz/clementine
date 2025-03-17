use std::collections::{HashMap, HashSet};

use bitcoin::{OutPoint, Witness};
use eyre::Report;
use serde_with::serde_as;
use statig::prelude::*;

use crate::{
    builder::transaction::{
        remove_txhandler_from_map, ContractContext, DepositData, TransactionType,
    },
    errors::BridgeError,
    rpc::clementine::KickoffId,
};

use super::{
    block_cache::BlockCache,
    context::{Duty, StateContext},
    matcher::{BlockMatcher, Matcher},
    Owner,
};

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum KickoffEvent {
    Challenged,
    WatchtowerChallengeSent {
        watchtower_idx: usize,
        challenge_outpoint: OutPoint,
    },
    OperatorAssertSent {
        assert_idx: usize,
        assert_outpoint: OutPoint,
    },
    WatchtowerChallengeTimeoutSent {
        watchtower_idx: usize,
    },
    OperatorChallengeAckSent {
        watchtower_idx: usize,
        challenge_ack_outpoint: OutPoint,
    },
    KickoffFinalizerSpent,
    BurnConnectorSpent,
    // TODO: add warnings
    // ChallengeTimeoutNotSent,
    TimeToSendWatchtowerChallenge,
    TimeToSendVerifierDisprove,
    /// Special event that is used to indicate that the state machine has been saved to the database and the dirty flag should be reset
    SavedToDb,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
// TODO: add and save operator challenge acks
// all timelocks
// delete used matchers
// apply only first match

pub struct KickoffStateMachine<T: Owner> {
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) matchers: HashMap<Matcher, KickoffEvent>,
    pub(crate) dirty: bool,
    pub(crate) kickoff_id: KickoffId,
    deposit_data: DepositData,
    kickoff_height: u32,
    payout_blockhash: Witness,
    spent_watchtower_utxos: HashSet<usize>,
    watchtower_challenges: HashMap<usize, Witness>,
    operator_asserts: HashMap<usize, Witness>,
    operator_challenge_acks: HashMap<usize, Witness>,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Owner> BlockMatcher for KickoffStateMachine<T> {
    type StateEvent = KickoffEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::StateEvent> {
        self.matchers
            .iter()
            .filter_map(|(matcher, kickoff_event)| {
                matcher.matches(block).map(|ord| (ord, kickoff_event))
            })
            .min()
            .map(|(_, kickoff_event)| kickoff_event)
            .into_iter()
            .cloned()
            .collect()
    }
}

impl<T: Owner> KickoffStateMachine<T> {
    // TODO: num_operators and num_watchtowers in deposit_data in the future
    pub fn new(
        kickoff_id: KickoffId,
        kickoff_height: u32,
        deposit_data: DepositData,
        payout_blockhash: Witness,
    ) -> Self {
        Self {
            kickoff_id,
            kickoff_height,
            deposit_data,
            payout_blockhash,
            matchers: HashMap::new(),
            dirty: true,
            phantom: std::marker::PhantomData,
            watchtower_challenges: HashMap::new(),
            operator_asserts: HashMap::new(),
            spent_watchtower_utxos: HashSet::new(),
            operator_challenge_acks: HashMap::new(),
        }
    }
}

#[state_machine(
    initial = "State::kickoff_started()",
    on_dispatch = "Self::on_dispatch",
    on_transition = "Self::on_transition",
    state(derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize))
)]
impl<T: Owner> KickoffStateMachine<T> {
    #[action]
    pub(crate) fn on_transition(&mut self, state_a: &State, state_b: &State) {
        tracing::trace!(?self.kickoff_id, ?self.deposit_data, "Transitioning from {:?} to {:?}", state_a, state_b);
        self.dirty = true;
    }
    pub fn wrap_err(
        &'_ self,
        method: &'static str,
    ) -> impl FnOnce(BridgeError) -> eyre::Report + '_ {
        move |e| {
            Report::from(e).wrap_err(format!(
                "Error in kickoff state machine for kickoff {:?} in {}",
                self.kickoff_id, method
            ))
        }
    }

    #[action]
    pub(crate) fn on_dispatch(
        &mut self,
        _state: StateOrSuperstate<'_, '_, Self>,
        evt: &KickoffEvent,
    ) {
        if matches!(evt, KickoffEvent::SavedToDb) {
            self.dirty = false;
        } else {
            tracing::debug!(?self.kickoff_id, "Dispatching event {:?}", evt);
            self.dirty = true;

            // Remove the matcher corresponding to the event.
            if let Some((matcher, _)) = self.matchers.iter().find(|(_, ev)| ev == &evt) {
                let matcher = matcher.clone();
                self.matchers.remove(&matcher);
            }
        }
    }

    async fn check_if_time_to_send_asserts(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    // if all watchtower challenge utxos are spent, its safe to send asserts
                    if self.spent_watchtower_utxos.len() == context.paramset.num_watchtowers {
                        context
                            .owner
                            .handle_duty(Duty::SendOperatorAsserts {
                                kickoff_id: self.kickoff_id,
                                deposit_data: self.deposit_data.clone(),
                                watchtower_challenges: self.watchtower_challenges.clone(),
                                payout_blockhash: self.payout_blockhash.clone(),
                            })
                            .await?;
                    }
                    Ok(())
                }
                .map_err(self.wrap_err("on send_asserts"))
            })
            .await;
    }

    async fn send_watchtower_challenge(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    context
                        .owner
                        .handle_duty(Duty::WatchtowerChallenge {
                            kickoff_id: self.kickoff_id,
                            deposit_data: self.deposit_data.clone(),
                        })
                        .await?;
                    Ok(())
                }
                .map_err(self.wrap_err("on send_watchtower_challenge"))
            })
            .await;
    }

    async fn send_disprove(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    context
                        .owner
                        .handle_duty(Duty::VerifierDisprove {
                            kickoff_id: self.kickoff_id,
                            deposit_data: self.deposit_data.clone(),
                            operator_asserts: self.operator_asserts.clone(),
                            operator_acks: self.operator_challenge_acks.clone(),
                            payout_blockhash: self.payout_blockhash.clone(),
                        })
                        .await?;
                    Ok(())
                }
                .map_err(self.wrap_err("on_check_time_to_send_asserts"))
            })
            .await;
    }

    async fn unhandled_event(&mut self, context: &mut StateContext<T>, event: &KickoffEvent) {
        context
            .capture_error(async |_context| {
                let event_str = format!("{:?}", event);
                Err(BridgeError::UnhandledEvent(event_str))
                    .map_err(self.wrap_err("kickoff unhandled event"))
            })
            .await;
    }

    #[action]
    pub(crate) async fn on_challenged_entry(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    // create times to send necessary challenge asserts
                    self.matchers.insert(
                        Matcher::BlockHeight(
                            self.kickoff_height
                                + context.paramset.time_to_send_watchtower_challenge as u32,
                        ),
                        KickoffEvent::TimeToSendWatchtowerChallenge,
                    );
                    self.matchers.insert(
                        Matcher::BlockHeight(
                            self.kickoff_height + context.paramset.time_to_disprove as u32,
                        ),
                        KickoffEvent::TimeToSendVerifierDisprove,
                    );
                    Ok(())
                }
                .map_err(self.wrap_err("on_kickoff_started_entry"))
            })
            .await;
    }

    #[state(superstate = "kickoff", entry_action = "on_challenged_entry")]
    pub(crate) async fn challenged(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            KickoffEvent::WatchtowerChallengeSent { .. }
            | KickoffEvent::OperatorAssertSent { .. }
            | KickoffEvent::OperatorChallengeAckSent { .. }
            | KickoffEvent::KickoffFinalizerSpent
            | KickoffEvent::BurnConnectorSpent
            | KickoffEvent::WatchtowerChallengeTimeoutSent { .. }
            | KickoffEvent::SavedToDb => Super,
            KickoffEvent::TimeToSendWatchtowerChallenge => {
                self.send_watchtower_challenge(context).await;
                Handled
            }
            KickoffEvent::TimeToSendVerifierDisprove => {
                self.send_disprove(context).await;
                Handled
            }
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    #[superstate]
    async fn kickoff(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        tracing::trace!("Received event in kickoff superstate: {:?}", event);
        match event {
            KickoffEvent::WatchtowerChallengeSent {
                watchtower_idx,
                challenge_outpoint,
            } => {
                self.spent_watchtower_utxos.insert(*watchtower_idx);
                let witness = context
                    .cache
                    .get_witness_of_utxo(challenge_outpoint)
                    .expect("Challenge outpoint that got matched should be in block");
                // save challenge witness
                self.watchtower_challenges.insert(*watchtower_idx, witness);
                self.check_if_time_to_send_asserts(context).await;
                Handled
            }
            KickoffEvent::OperatorAssertSent {
                assert_idx,
                assert_outpoint,
            } => {
                let witness = context
                    .cache
                    .get_witness_of_utxo(assert_outpoint)
                    .expect("Assert outpoint that got matched should be in block");
                // save assert witness
                self.operator_asserts.insert(*assert_idx, witness);
                Handled
            }
            KickoffEvent::OperatorChallengeAckSent {
                watchtower_idx,
                challenge_ack_outpoint,
            } => {
                let witness = context
                    .cache
                    .get_witness_of_utxo(challenge_ack_outpoint)
                    .expect("Challenge ack outpoint that got matched should be in block");
                // save challenge ack witness
                self.operator_challenge_acks
                    .insert(*watchtower_idx, witness);
                Handled
            }
            KickoffEvent::KickoffFinalizerSpent => Transition(State::closed()),
            KickoffEvent::BurnConnectorSpent => {
                tracing::error!(
                    "Burn connector spent before kickoff was finalized for kickoff {:?}",
                    self.kickoff_id
                );
                Transition(State::closed())
            }
            KickoffEvent::WatchtowerChallengeTimeoutSent { watchtower_idx } => {
                self.spent_watchtower_utxos.insert(*watchtower_idx);
                self.check_if_time_to_send_asserts(context).await;
                Handled
            }
            KickoffEvent::SavedToDb => Handled,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    #[state(superstate = "kickoff", entry_action = "on_kickoff_started_entry")]
    pub(crate) async fn kickoff_started(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            KickoffEvent::Challenged => {
                tracing::warn!("Warning: Operator challenged: {:?}", self.kickoff_id);
                Transition(State::challenged())
            }
            KickoffEvent::WatchtowerChallengeSent { .. }
            | KickoffEvent::OperatorAssertSent { .. }
            | KickoffEvent::OperatorChallengeAckSent { .. }
            | KickoffEvent::KickoffFinalizerSpent
            | KickoffEvent::BurnConnectorSpent
            | KickoffEvent::WatchtowerChallengeTimeoutSent { .. }
            | KickoffEvent::SavedToDb => Super,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    async fn add_default_kickoff_matchers(
        &mut self,
        context: &mut StateContext<T>,
    ) -> Result<(), BridgeError> {
        let contract_context = ContractContext::new_context_for_kickoffs(
            self.kickoff_id,
            self.deposit_data.clone(),
            context.paramset,
        );
        let mut txhandlers = context
            .owner
            .create_txhandlers(TransactionType::AllNeededForDeposit, contract_context)
            .await?;
        let kickoff_txhandler =
            remove_txhandler_from_map(&mut txhandlers, TransactionType::Kickoff)?;

        // add operator asserts
        let kickoff_txid = *kickoff_txhandler.get_txid();
        let num_asserts = crate::bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs();
        for assert_idx in 0..num_asserts {
            // TODO: use dedicated functions or smth else, not hardcoded here.
            // It will be easier when we have data of operators/watchtowers that participated in the deposit in DepositData
            let mini_assert_vout = 4 + assert_idx;
            let assert_timeout_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::AssertTimeout(assert_idx),
            )?;
            let assert_timeout_txid = assert_timeout_txhandler.get_txid();
            self.matchers.insert(
                Matcher::SpentUtxoButNotTimeout(
                    OutPoint {
                        txid: kickoff_txid,
                        vout: mini_assert_vout as u32,
                    },
                    *assert_timeout_txid,
                ),
                KickoffEvent::OperatorAssertSent {
                    assert_outpoint: OutPoint {
                        txid: kickoff_txid,
                        vout: mini_assert_vout as u32,
                    },
                    assert_idx,
                },
            );
        }
        // add watchtower challenges and challenge acks
        for watchtower_idx in 0..context.paramset.num_watchtowers {
            // TODO: use dedicated functions or smth else, not hardcoded here.
            // It will be easier when we have data of operators/watchtowers that participated in the deposit in DepositData
            let watchtower_challenge_vout = 4 + num_asserts + watchtower_idx * 2;
            let watchtower_timeout_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::WatchtowerChallengeTimeout(watchtower_idx),
            )?;
            let watchtower_timeout_txid = watchtower_timeout_txhandler.get_txid();
            // matcher in case timeout is sent
            self.matchers.insert(
                Matcher::SentTx(*watchtower_timeout_txid),
                KickoffEvent::WatchtowerChallengeTimeoutSent { watchtower_idx },
            );
            // martcher in case watchtower challenge is sent
            self.matchers.insert(
                Matcher::SpentUtxoButNotTimeout(
                    OutPoint {
                        txid: kickoff_txid,
                        vout: watchtower_challenge_vout as u32,
                    },
                    *watchtower_timeout_txid,
                ),
                KickoffEvent::WatchtowerChallengeSent {
                    watchtower_idx,
                    challenge_outpoint: OutPoint {
                        txid: kickoff_txid,
                        vout: watchtower_challenge_vout as u32,
                    },
                },
            );
            // add operator challenge ack
            let operator_challenge_ack_vout = watchtower_challenge_vout + 1;
            let operator_challenge_nack_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::OperatorChallengeNack(watchtower_idx),
            )?;
            let operator_challenge_nack_txid = operator_challenge_nack_txhandler.get_txid();
            self.matchers.insert(
                Matcher::SpentUtxoButNotTimeout(
                    OutPoint {
                        txid: kickoff_txid,
                        vout: operator_challenge_ack_vout as u32,
                    },
                    *operator_challenge_nack_txid,
                ),
                KickoffEvent::OperatorChallengeAckSent {
                    watchtower_idx,
                    challenge_ack_outpoint: OutPoint {
                        txid: kickoff_txid,
                        vout: operator_challenge_ack_vout as u32,
                    },
                },
            );
        }

        // add burn connector tx spent matcher
        let round_txhandler = remove_txhandler_from_map(&mut txhandlers, TransactionType::Round)?;
        let round_txid = *round_txhandler.get_txid();
        self.matchers.insert(
            Matcher::SpentUtxo(OutPoint {
                txid: round_txid,
                vout: 0,
            }),
            KickoffEvent::BurnConnectorSpent,
        );
        // add kickoff finalizer tx spent matcher
        self.matchers.insert(
            Matcher::SpentUtxo(OutPoint {
                txid: kickoff_txid,
                vout: 1,
            }),
            KickoffEvent::KickoffFinalizerSpent,
        );
        // add challenge tx
        let challenge_vout = 0;
        let challenge_timeout_txhandler =
            remove_txhandler_from_map(&mut txhandlers, TransactionType::ChallengeTimeout)?;
        let challenge_timeout_txid = challenge_timeout_txhandler.get_txid();
        self.matchers.insert(
            Matcher::SpentUtxoButNotTimeout(
                OutPoint {
                    txid: kickoff_txid,
                    vout: challenge_vout,
                },
                *challenge_timeout_txid,
            ),
            KickoffEvent::Challenged,
        );
        Ok(())
    }

    #[action]
    pub(crate) async fn on_kickoff_started_entry(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    // Add all watchtower challenges and operator asserts to matchers
                    self.add_default_kickoff_matchers(context).await?;
                    Ok(())
                }
                .map_err(self.wrap_err("on_kickoff_started_entry"))
            })
            .await;
    }

    #[action]
    #[allow(unused_variables)]
    pub(crate) async fn on_closed_entry(&mut self, context: &mut StateContext<T>) {
        self.matchers.clear();
    }

    #[state(entry_action = "on_closed_entry")]
    // Terminal state
    #[allow(unused_variables)]
    pub(crate) async fn closed(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        Handled
    }
}
