use std::collections::{HashMap, HashSet};

use bitcoin::{OutPoint, Transaction, Witness};
use eyre::Context;
use serde_with::serde_as;
use statig::prelude::*;

use crate::{
    bitvm_client::ClementineBitVMPublicKeys,
    builder::transaction::{
        input::UtxoVout, remove_txhandler_from_map, ContractContext, TransactionType,
    },
    deposit::{DepositData, KickoffData},
    errors::BridgeError,
};

use super::{
    block_cache::BlockCache,
    context::{Duty, StateContext},
    matcher::{BlockMatcher, Matcher},
    Owner, StateMachineError,
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
    LatestBlockHashSent {
        latest_blockhash_outpoint: OutPoint,
    },
    KickoffFinalizerSpent,
    BurnConnectorSpent,
    /// Special event that is used to indicate that it is time for the owner to send latest blockhash tx.
    /// Matcher for this event is created after all watchtower challenge utxos are spent.
    /// Latest blockhash is sent some blocks after all watchtower challenge utxos are spent, so that the total work until the block commiitted
    /// in latest blockhash is definitely higher than the highest work in valid watchtower challenges.
    TimeToSendLatestBlockhash,
    TimeToSendWatchtowerChallenge,
    /// Special event that is used to indicate that the state machine has been saved to the database and the dirty flag should be reset
    SavedToDb,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KickoffStateMachine<T: Owner> {
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) matchers: HashMap<Matcher, KickoffEvent>,
    pub(crate) dirty: bool,
    pub(crate) kickoff_data: KickoffData,
    deposit_data: DepositData,
    kickoff_height: u32,
    payout_blockhash: Witness,
    spent_watchtower_utxos: HashSet<usize>,
    latest_blockhash: Witness,
    watchtower_challenges: HashMap<usize, Transaction>,
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
    pub fn new(
        kickoff_data: KickoffData,
        kickoff_height: u32,
        deposit_data: DepositData,
        payout_blockhash: Witness,
    ) -> Self {
        Self {
            kickoff_data,
            kickoff_height,
            deposit_data,
            payout_blockhash,
            latest_blockhash: Witness::default(),
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
        tracing::trace!(?self.kickoff_data, ?self.deposit_data, "Transitioning from {:?} to {:?}", state_a, state_b);
        self.dirty = true;
    }

    pub fn kickoff_meta(&self, method: &'static str) -> StateMachineError {
        eyre::eyre!(
            "Error in kickoff state machine for kickoff {:?} in {}",
            self.kickoff_data,
            method
        )
        .into()
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
            tracing::trace!(?self.kickoff_data, "Dispatching event {:?}", evt);
            self.dirty = true;

            // Remove the matcher corresponding to the event.
            if let Some((matcher, _)) = self.matchers.iter().find(|(_, ev)| ev == &evt) {
                let matcher = matcher.clone();
                self.matchers.remove(&matcher);
            }
        }
    }

    async fn create_matcher_for_latest_blockhash_if_ready(
        &mut self,
        context: &mut StateContext<T>,
    ) {
        context
            .capture_error(async |context| {
                {
                    // if all watchtower challenge utxos are spent, its safe to send asserts
                    if self.spent_watchtower_utxos.len() == self.deposit_data.get_num_watchtowers()
                    {
                        // create a matcher to send latest blockhash tx after finality depth blocks pass from current block height
                        self.matchers.insert(
                            Matcher::BlockHeight(
                                context.cache.block_height + context.paramset.finality_depth,
                            ),
                            KickoffEvent::TimeToSendLatestBlockhash,
                        );
                    }
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on check_if_time_to_commit_latest_blockhash"))
            })
            .await;
    }

    async fn disprove_if_ready(&mut self, context: &mut StateContext<T>) {
        if self.operator_asserts.len() == ClementineBitVMPublicKeys::number_of_assert_txs()
            && self.latest_blockhash != Witness::default()
            && self.spent_watchtower_utxos.len() == self.deposit_data.get_num_watchtowers()
        {
            self.send_disprove(context).await;
        }
    }

    async fn send_operator_asserts(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    // if all watchtower challenge utxos are spent and latest blockhash is committed, its safe to send asserts
                    if self.spent_watchtower_utxos.len() == self.deposit_data.get_num_verifiers()
                        && self.latest_blockhash != Witness::default()
                    {
                        context
                            .owner
                            .handle_duty(Duty::SendOperatorAsserts {
                                kickoff_data: self.kickoff_data,
                                deposit_data: self.deposit_data.clone(),
                                watchtower_challenges: self.watchtower_challenges.clone(),
                                payout_blockhash: self.payout_blockhash.clone(),
                                latest_blockhash: self.latest_blockhash.clone(),
                            })
                            .await?;
                    }
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on send_operator_asserts"))
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
                            kickoff_data: self.kickoff_data,
                            deposit_data: self.deposit_data.clone(),
                        })
                        .await?;
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on send_watchtower_challenge"))
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
                            kickoff_data: self.kickoff_data,
                            deposit_data: self.deposit_data.clone(),
                            operator_asserts: self.operator_asserts.clone(),
                            operator_acks: self.operator_challenge_acks.clone(),
                            payout_blockhash: self.payout_blockhash.clone(),
                            latest_blockhash: self.latest_blockhash.clone(),
                        })
                        .await?;
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on send_disprove"))
            })
            .await;
    }

    async fn send_latest_blockhash(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    context
                        .owner
                        .handle_duty(Duty::SendLatestBlockhash {
                            kickoff_data: self.kickoff_data,
                            deposit_data: self.deposit_data.clone(),
                            latest_blockhash: context
                                .cache
                                .block
                                .as_ref()
                                .ok_or(eyre::eyre!("Block object not found in block cache"))?
                                .header
                                .block_hash(),
                        })
                        .await?;
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on send_latest_blockhash"))
            })
            .await;
    }

    async fn unhandled_event(&mut self, context: &mut StateContext<T>, event: &KickoffEvent) {
        context
            .capture_error(async |_context| {
                let event_str = format!("{:?}", event);
                Err(StateMachineError::UnhandledEvent(event_str))
                    .wrap_err(self.kickoff_meta("kickoff unhandled event"))
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
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on_kickoff_started_entry"))
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
            | KickoffEvent::LatestBlockHashSent { .. }
            | KickoffEvent::SavedToDb => Super,
            KickoffEvent::TimeToSendWatchtowerChallenge => {
                self.send_watchtower_challenge(context).await;
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
                let tx = context
                    .cache
                    .get_tx_of_utxo(challenge_outpoint)
                    .expect("Challenge outpoint that got matched should be in block");
                // save challenge witness
                self.watchtower_challenges
                    .insert(*watchtower_idx, tx.clone());
                self.create_matcher_for_latest_blockhash_if_ready(context)
                    .await;
                self.disprove_if_ready(context).await;
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
                self.disprove_if_ready(context).await;
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
                    self.kickoff_data
                );
                Transition(State::closed())
            }
            KickoffEvent::WatchtowerChallengeTimeoutSent { watchtower_idx } => {
                self.spent_watchtower_utxos.insert(*watchtower_idx);
                self.create_matcher_for_latest_blockhash_if_ready(context)
                    .await;
                Handled
            }
            KickoffEvent::LatestBlockHashSent {
                latest_blockhash_outpoint,
            } => {
                let witness = context
                    .cache
                    .get_witness_of_utxo(latest_blockhash_outpoint)
                    .expect("Latest blockhash outpoint that got matched should be in block");
                // save latest blockhash witness
                self.latest_blockhash = witness;
                // can start sending asserts as latest blockhash is committed and finalized
                self.send_operator_asserts(context).await;
                self.disprove_if_ready(context).await;
                Handled
            }
            KickoffEvent::TimeToSendLatestBlockhash => {
                // tell owner to send latest blockhash tx
                self.send_latest_blockhash(context).await;
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
                tracing::warn!("Warning: Operator challenged: {:?}", self.kickoff_data);
                Transition(State::challenged())
            }
            KickoffEvent::WatchtowerChallengeSent { .. }
            | KickoffEvent::OperatorAssertSent { .. }
            | KickoffEvent::OperatorChallengeAckSent { .. }
            | KickoffEvent::KickoffFinalizerSpent
            | KickoffEvent::BurnConnectorSpent
            | KickoffEvent::WatchtowerChallengeTimeoutSent { .. }
            | KickoffEvent::LatestBlockHashSent { .. }
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
        let contract_context = ContractContext::new_context_for_kickoff(
            self.kickoff_data,
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
            let mini_assert_vout = UtxoVout::Assert(assert_idx).get_vout();
            let assert_timeout_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::AssertTimeout(assert_idx),
            )?;
            let assert_timeout_txid = assert_timeout_txhandler.get_txid();
            self.matchers.insert(
                Matcher::SpentUtxoButNotTxid(
                    OutPoint {
                        txid: kickoff_txid,
                        vout: mini_assert_vout,
                    },
                    vec![*assert_timeout_txid],
                ),
                KickoffEvent::OperatorAssertSent {
                    assert_outpoint: OutPoint {
                        txid: kickoff_txid,
                        vout: mini_assert_vout,
                    },
                    assert_idx,
                },
            );
        }
        // add latest blockhash tx sent matcher
        let latest_blockhash_timeout_txhandler =
            remove_txhandler_from_map(&mut txhandlers, TransactionType::LatestBlockhashTimeout)?;
        let latest_blockhash_timeout_txid = latest_blockhash_timeout_txhandler.get_txid();
        let latest_blockhash_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: UtxoVout::LatestBlockhash.get_vout(),
        };
        self.matchers.insert(
            Matcher::SpentUtxoButNotTxid(
                latest_blockhash_outpoint,
                vec![*latest_blockhash_timeout_txid],
            ),
            KickoffEvent::LatestBlockHashSent {
                latest_blockhash_outpoint,
            },
        );
        // add watchtower challenges and challenge acks
        for watchtower_idx in 0..self.deposit_data.get_num_watchtowers() {
            let watchtower_challenge_vout =
                UtxoVout::WatchtowerChallenge(watchtower_idx).get_vout();
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
                Matcher::SpentUtxoButNotTxid(
                    OutPoint {
                        txid: kickoff_txid,
                        vout: watchtower_challenge_vout,
                    },
                    vec![*watchtower_timeout_txid],
                ),
                KickoffEvent::WatchtowerChallengeSent {
                    watchtower_idx,
                    challenge_outpoint: OutPoint {
                        txid: kickoff_txid,
                        vout: watchtower_challenge_vout,
                    },
                },
            );
            // add operator challenge ack
            let operator_challenge_ack_vout =
                UtxoVout::WatchtowerChallengeAck(watchtower_idx).get_vout();
            let operator_challenge_nack_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::OperatorChallengeNack(watchtower_idx),
            )?;
            let operator_challenge_nack_txid = operator_challenge_nack_txhandler.get_txid();
            self.matchers.insert(
                Matcher::SpentUtxoButNotTxid(
                    OutPoint {
                        txid: kickoff_txid,
                        vout: operator_challenge_ack_vout,
                    },
                    vec![*operator_challenge_nack_txid, *watchtower_timeout_txid],
                ),
                KickoffEvent::OperatorChallengeAckSent {
                    watchtower_idx,
                    challenge_ack_outpoint: OutPoint {
                        txid: kickoff_txid,
                        vout: operator_challenge_ack_vout,
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
                vout: UtxoVout::CollateralInRound.get_vout(),
            }),
            KickoffEvent::BurnConnectorSpent,
        );
        // add kickoff finalizer tx spent matcher
        self.matchers.insert(
            Matcher::SpentUtxo(OutPoint {
                txid: kickoff_txid,
                vout: UtxoVout::KickoffFinalizer.get_vout(),
            }),
            KickoffEvent::KickoffFinalizerSpent,
        );
        // add challenge tx
        let challenge_timeout_txhandler =
            remove_txhandler_from_map(&mut txhandlers, TransactionType::ChallengeTimeout)?;
        let challenge_timeout_txid = challenge_timeout_txhandler.get_txid();
        self.matchers.insert(
            Matcher::SpentUtxoButNotTxid(
                OutPoint {
                    txid: kickoff_txid,
                    vout: UtxoVout::Challenge.get_vout(),
                },
                vec![*challenge_timeout_txid],
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
                    Ok::<(), BridgeError>(())
                }
                .wrap_err(self.kickoff_meta("on_kickoff_started_entry"))
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
