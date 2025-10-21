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

/// Events that can be dispatched to the kickoff state machine
/// These event either trigger state transitions or trigger actions of the owner
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub enum KickoffEvent {
    /// Event that is dispatched when the kickoff is challenged
    /// This will change the state to "Challenged"
    Challenged,
    /// Event that is dispatched when a watchtower challenge is detected in Bitcoin
    WatchtowerChallengeSent {
        watchtower_idx: usize,
        challenge_outpoint: OutPoint,
    },
    /// Event that is dispatched when an operator BitVM assert is detected in Bitcoin
    OperatorAssertSent {
        assert_idx: usize,
        assert_outpoint: OutPoint,
    },
    /// Event that is dispatched when a watchtower challenge timeout is detected in Bitcoin
    WatchtowerChallengeTimeoutSent { watchtower_idx: usize },
    /// Event that is dispatched when an operator challenge ack is detected in Bitcoin
    /// Operator challenge acks are sent by operators to acknowledge watchtower challenges
    OperatorChallengeAckSent {
        watchtower_idx: usize,
        challenge_ack_outpoint: OutPoint,
    },
    /// Event that is dispatched when the latest blockhash is detected in Bitcoin
    LatestBlockHashSent { latest_blockhash_outpoint: OutPoint },
    /// Event that is dispatched when the kickoff finalizer is spent in Bitcoin
    /// Irrespective of whether the kickoff is malicious or not, the kickoff process is finished when the kickoff finalizer is spent.
    KickoffFinalizerSpent,
    /// Event that is dispatched when the burn connector is spent in Bitcoin
    BurnConnectorSpent,
    /// Vvent that is used to indicate that it is time for the owner to send latest blockhash tx.
    /// Matcher for this event is created after all watchtower challenge utxos are spent.
    /// Latest blockhash is sent some blocks after all watchtower challenge utxos are spent, so that the total work until the block commiitted
    /// in latest blockhash is definitely higher than the highest work in valid watchtower challenges.
    TimeToSendLatestBlockhash,
    /// Event that is used to indicate that it is time for the owner to send watchtower challenge tx.
    /// Watchtower challenges are sent after some blocks pass since the kickoff tx, so that the total work in the watchtower challenge is as high as possible.
    TimeToSendWatchtowerChallenge,
    /// Special event that is used to indicate that the state machine has been saved to the database and the dirty flag should be reset to false
    SavedToDb,
}

/// State machine for tracking a single kickoff process in the protocol.
///
/// # Purpose
/// The `KickoffStateMachine` manages the lifecycle of a single kickoff process, which is created after a kickoff transaction is detected on Bitcoin. It tracks the transactions related to the kickoff and the resulting data.
///
/// # States
/// - `kickoff_started`: The initial state after a kickoff is detected. Waits for further events such as challenges, but still tracks any committed data on Bitcoin (like latest blockhash, operator asserts, watchtower challenges, etc)
/// - `challenged`: Entered if the kickoff is challenged. Watchtower challenges are only sent if the kickoff is challenged.
/// - `closed`: Terminal state indicating the kickoff process has ended, either by kickoff finalizer utxo or burn connector utxo being spent.
///
/// # Events
/// - `Challenged`: The kickoff is challenged, transitioning to the `challenged` state.
/// - `WatchtowerChallengeSent`: A watchtower challenge is detected on Bitcoin, stores the watchtower challenge transaction, and stores the watchtower utxo as spent.
/// - `OperatorAssertSent`: An operator BitVM assert is detected, stores the witness of the assert utxo.
/// - `WatchtowerChallengeTimeoutSent`: A watchtower challenge timeout is detected, stores watchtower utxo as spent.
/// - `OperatorChallengeAckSent`: An operator challenge acknowledgment is detected, stores the witness of the challenge ack utxo, which holds the revealed preimage that can be used to disprove if the operator maliciously doesn't include the watchtower challenge in the BitVM proof. After sending this transaction, the operator is forced to use the corresponding watchtower challenge in its BitVM proof, otherwise it can be disproven.
/// - `LatestBlockHashSent`: The latest blockhash is committed on Bitcoin, stores the witness of the latest blockhash utxo, which holds the blockhash that should be used by the operator in its BitVM proof.
/// - `KickoffFinalizerSpent`: The kickoff finalizer is spent, ending the kickoff process, transitions to the `closed` state.
/// - `BurnConnectorSpent`: The burn connector is spent, ending the kickoff process, transitions to the `closed` state.
/// - `TimeToSendWatchtowerChallenge`: Time to send a watchtower challenge (used in challenged state), this event notifies the owner to create and send a watchtower challenge tx. Verifiers wait after a kickoff to send a watchtower challenge so that the total work in the watchtower challenge is as high as possible.
/// - `SavedToDb`: Indicates the state machine has been persisted and resets the dirty flag.
///
/// # Behavior
/// - The state machine maintains a set of matchers to detect relevant Bitcoin transactions and trigger corresponding events.
/// - It tracks the progress of the kickoff, including challenges, operator actions, and finalization.
/// - When terminal events occur (e.g., finalizer or burn connector spent), the state machine transitions to `closed` and clears all matchers.
/// - The state machine interacts with the owner to perform protocol duties (e.g., sending challenges, asserts, or disproves) as required by the protocol logic.
///
/// This design ensures that all protocol-critical events related to a kickoff are tracked and handled in a robust, stateful manner, supporting both normal and adversarial scenarios.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KickoffStateMachine<T: Owner> {
    /// Maps matchers to the resulting kickoff events.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) matchers: HashMap<Matcher, KickoffEvent>,
    /// Indicates if the state machine has unsaved changes that need to be persisted on db.
    /// dirty flag is set if any matcher matches the current block.
    /// the flag is set to true in on_transition and on_dispatch
    /// the flag is set to false after the state machine is saved to db and the event SavedToDb is dispatched
    pub(crate) dirty: bool,
    /// The kickoff data associated with the kickoff being tracked.
    pub(crate) kickoff_data: KickoffData,
    /// The deposit data that the kickoff tries to withdraw from.
    pub(crate) deposit_data: DepositData,
    /// The block height at which the kickoff transaction was mined.
    pub(crate) kickoff_height: u32,
    /// The witness for the kickoff transactions input which is a winternitz signature that commits the payout blockhash.
    pub(crate) payout_blockhash: Witness,
    /// Marker to indicate if the state machine is in the challenged state.
    challenged: bool,
    /// Set of indices of watchtower UTXOs that have already been spent.
    spent_watchtower_utxos: HashSet<usize>,
    /// The witness taken from the transaction spending the latest blockhash utxo.
    latest_blockhash: Witness,
    /// Saves watchtower challenges with the watchtower index as the key.
    /// Watchtower challenges are encoded as the output of the watchtower challenge tx.
    /// (taproot addresses parsed as 32 bytes + OP_RETURN data), in total 144 bytes.
    watchtower_challenges: HashMap<usize, Transaction>,
    /// Saves operator asserts with the index of the assert utxo as the key.
    /// Operator asserts are witnesses that spend the assert utxo's and contain the winternitz signature of the BitVM assertion.
    operator_asserts: HashMap<usize, Witness>,
    /// Saves operator challenge acks with the index of the challenge ack utxo as the key.
    /// Operator challenge acks are witnesses that spend the challenge ack utxo's.
    /// The witness contains the revealed preimage that can be used to disprove if the operator
    /// maliciously doesn't include the watchtower challenge in the BitVM proof.
    operator_challenge_acks: HashMap<usize, Witness>,
    /// Marker for the generic owner type (phantom data for type safety).
    /// This is used to ensure that the state machine is generic over the owner type.
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
            challenged: false,
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

    /// Checks if the latest blockhash is ready to be committed on Bitcoin.
    /// The check is done by checking if all watchtower challenge utxos are spent.
    /// If the check is successful, the a new matcher is created to send latest blockhash tx after finality depth blocks pass from current block height.
    async fn create_matcher_for_latest_blockhash_if_ready(
        &mut self,
        context: &mut StateContext<T>,
    ) {
        context
            .capture_error(async |context| {
                {
                    // if all watchtower challenge utxos are spent, its safe to send latest blockhash commit tx
                    if self.challenged
                        && self.spent_watchtower_utxos.len()
                            == self.deposit_data.get_num_watchtowers()
                    {
                        // create a matcher to send latest blockhash tx after finality depth blocks pass from current block height
                        self.matchers.insert(
                            Matcher::BlockHeight(
                                context.cache.block_height + context.paramset.finality_depth - 1,
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

    /// Checks if the disprove is ready to be sent on Bitcoin
    /// The check is done by checking if all operator asserts are received,
    /// latest blockhash is committed and all watchtower challenge utxos are spent
    /// If the check is successful, the disprove is sent on Bitcoin
    async fn disprove_if_ready(&mut self, context: &mut StateContext<T>) {
        if self.challenged && self.operator_asserts.len() == ClementineBitVMPublicKeys::number_of_assert_txs()
            && self.latest_blockhash != Witness::default()
            && self.spent_watchtower_utxos.len() == self.deposit_data.get_num_watchtowers()
            // check if all operator acks are received, one ack for each watchtower challenge
            // to make sure we have all preimages required to disprove if operator didn't include 
            // the watchtower challenge in the BitVM proof
            && self.watchtower_challenges.keys().all(|idx| self.operator_challenge_acks.contains_key(idx))
        {
            self.send_disprove(context).await;
        }
    }

    /// Checks if the operator asserts are ready to be sent on Bitcoin
    /// The check is done by checking if all watchtower challenge utxos are spent and latest blockhash is committed
    /// If the check is successful, the operator asserts are sent on Bitcoin
    async fn send_operator_asserts_if_ready(&mut self, context: &mut StateContext<T>) {
        context
            .capture_error(async |context| {
                {
                    // if all watchtower challenge utxos are spent and latest blockhash is committed, its safe to send asserts
                    if self.challenged
                        && self.spent_watchtower_utxos.len()
                            == self.deposit_data.get_num_watchtowers()
                        && self.latest_blockhash != Witness::default()
                    {
                        context
                            .dispatch_duty(Duty::SendOperatorAsserts {
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
                        .dispatch_duty(Duty::WatchtowerChallenge {
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
                        .dispatch_duty(Duty::VerifierDisprove {
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
                        .dispatch_duty(Duty::SendLatestBlockhash {
                            kickoff_data: self.kickoff_data,
                            deposit_data: self.deposit_data.clone(),
                            latest_blockhash: context.cache.block.header.block_hash(),
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
                let event_str = format!("{event:?}");
                Err(StateMachineError::UnhandledEvent(event_str))
                    .wrap_err(self.kickoff_meta("kickoff unhandled event"))
            })
            .await;
    }

    /// If the kickoff is challenged, the state machine will add corresponding matchers for
    /// sending watchtower challenges after some amount of blocks passes since the kickoff was included in Bitcoin.
    /// Sending watchtower challenges only happen if the kickoff is challenged.
    /// As sending latest blockhash commit and asserts depend on watchtower challenges/timeouts being sent,
    /// they will also not be sent if the kickoff is not challenged and kickoff finalizer is spent with ChallengeTimeout,
    /// which changes the state to "Closed".
    #[action]
    pub(crate) async fn on_challenged_entry(&mut self, context: &mut StateContext<T>) {
        self.challenged = true;
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
        // check if any action is ready to be started as it could already be ready before a challenge arrives
        // but we want to make sure kickoff is actually challenged before we start sending actions
        self.create_matcher_for_latest_blockhash_if_ready(context)
            .await;
        self.send_operator_asserts_if_ready(context).await;
        self.disprove_if_ready(context).await;
    }

    /// State that is entered when the kickoff is challenged
    /// It only includes special handling for the TimeToSendWatchtowerChallenge event
    /// All other events are handled in the kickoff superstate
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
            | KickoffEvent::TimeToSendLatestBlockhash
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
            // When a watchtower challenge is detected in Bitcoin,
            // save the full challenge transaction and check if the latest blockhash can be committed
            // and if the disprove is ready to be sent
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
                self.send_operator_asserts_if_ready(context).await;
                self.disprove_if_ready(context).await;
                Handled
            }
            // When an operator assert is detected in Bitcoin,
            // save the assert witness (which is the BitVM winternitz commit)
            // and check if the disprove is ready to be sent
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
            // When an operator challenge ack is detected in Bitcoin,
            // save the ack witness as the witness includes the revealed preimage that
            // can be used to disprove if the operator maliciously doesn't include the
            // watchtower challenge in the BitVM proof
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
                self.disprove_if_ready(context).await;
                Handled
            }
            // When the kickoff finalizer is spent in Bitcoin,
            // the kickoff process is finished and the state machine will transition to the "Closed" state
            KickoffEvent::KickoffFinalizerSpent => Transition(State::closed()),
            // When the burn connector of the operator is spent in Bitcoin, it means the operator cannot continue with any more kickoffs
            // (unless burn connector is spent by ready to reimburse tx), so the state machine will transition to the "Closed" state
            KickoffEvent::BurnConnectorSpent => {
                tracing::error!(
                    "Burn connector spent before kickoff was finalized for kickoff {:?}",
                    self.kickoff_data
                );
                Transition(State::closed())
            }
            // When a watchtower challenge timeout is detected in Bitcoin,
            // set the watchtower utxo as spent and check if the latest blockhash can be committed
            KickoffEvent::WatchtowerChallengeTimeoutSent { watchtower_idx } => {
                self.spent_watchtower_utxos.insert(*watchtower_idx);
                self.create_matcher_for_latest_blockhash_if_ready(context)
                    .await;
                self.send_operator_asserts_if_ready(context).await;
                self.disprove_if_ready(context).await;
                Handled
            }
            // When the latest blockhash is detected in Bitcoin,
            // save the witness which includes the blockhash and check if the operator asserts and
            // disprove tx are ready to be sent
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
                self.send_operator_asserts_if_ready(context).await;
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

    /// State that is entered when the kickoff is started
    /// It will transition to the "Challenged" state if the kickoff is challenged
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
            | KickoffEvent::TimeToSendLatestBlockhash
            | KickoffEvent::SavedToDb => Super,
            _ => {
                self.unhandled_event(context, event).await;
                Handled
            }
        }
    }

    /// Adds the default matchers that will be used if the state is "challenged" or "kickoff_started".
    /// These matchers are used to detect when various transactions in the contract are mined on Bitcoin.
    async fn add_default_kickoff_matchers(
        &mut self,
        context: &mut StateContext<T>,
    ) -> Result<(), BridgeError> {
        // First create all transactions for the current deposit
        let contract_context = ContractContext::new_context_for_kickoff(
            self.kickoff_data,
            self.deposit_data.clone(),
            context.paramset,
        );
        let mut txhandlers = {
            let mut guard = context.shared_dbtx.lock().await;
            context
                .owner
                .create_txhandlers(
                    &mut guard,
                    TransactionType::AllNeededForDeposit,
                    contract_context,
                )
                .await?
        };
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
            // Assert transactions can have any txid (there is no enforcement on how the assert utxo is spent, just that
            // spending assert utxo reveals the BitVM winternitz commit in the utxo's witness)
            // But assert timeouts are nofn signed transactions with a fixed txid, so we can detect assert transactions
            // by checking if the assert utxo is spent but not by the assert timeout tx
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
        // Same logic as before with assert transaction detection, if latest blockhash utxo is not spent by latest blockhash timeout tx,
        // it means the latest blockhash is committed on Bitcoin
        self.matchers.insert(
            Matcher::SpentUtxoButNotTxid(
                latest_blockhash_outpoint,
                vec![*latest_blockhash_timeout_txid],
            ),
            KickoffEvent::LatestBlockHashSent {
                latest_blockhash_outpoint,
            },
        );
        // add watchtower challenges and challenge acks matchers
        for watchtower_idx in 0..self.deposit_data.get_num_watchtowers() {
            let watchtower_challenge_vout =
                UtxoVout::WatchtowerChallenge(watchtower_idx).get_vout();
            let watchtower_timeout_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::WatchtowerChallengeTimeout(watchtower_idx),
            )?;
            let watchtower_timeout_txid = watchtower_timeout_txhandler.get_txid();
            // matcher in case watchtower challenge timeout is sent
            self.matchers.insert(
                Matcher::SentTx(*watchtower_timeout_txid),
                KickoffEvent::WatchtowerChallengeTimeoutSent { watchtower_idx },
            );
            // matcher in case watchtower challenge is sent (watchtower challenge utxo is spent but not by watchtower challenge timeout tx)
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
            // add operator challenge ack matcher
            let operator_challenge_ack_vout =
                UtxoVout::WatchtowerChallengeAck(watchtower_idx).get_vout();
            let operator_challenge_nack_txhandler = remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::OperatorChallengeNack(watchtower_idx),
            )?;
            let operator_challenge_nack_txid = operator_challenge_nack_txhandler.get_txid();
            // operator challenge ack utxo is spent but not by operator challenge nack tx or watchtower challenge timeout tx
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
        // Burn connector can also be spent in ready to reimburse tx, but before spending burn connector that way,
        // the kickoff finalizer needs to be spent first, otherwise pre-signed "Kickoff not finalized" tx can be sent by
        // any verifier, slashing the operator.
        // If the kickoff finalizer is spent first, the state will be in "Closed" state and all matchers will be deleted.
        let round_txhandler = remove_txhandler_from_map(&mut txhandlers, TransactionType::Round)?;
        let round_txid = *round_txhandler.get_txid();
        self.matchers.insert(
            Matcher::SpentUtxo(OutPoint {
                txid: round_txid,
                vout: UtxoVout::CollateralInRound.get_vout(),
            }),
            KickoffEvent::BurnConnectorSpent,
        );
        // add kickoff finalizer utxo spent matcher
        self.matchers.insert(
            Matcher::SpentUtxo(OutPoint {
                txid: kickoff_txid,
                vout: UtxoVout::KickoffFinalizer.get_vout(),
            }),
            KickoffEvent::KickoffFinalizerSpent,
        );
        // add challenge detector matcher, if challenge utxo is not spent by challenge timeout tx, it means the kickoff is challenged
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

    /// Clears all matchers when the state is "closed".
    /// This means the state machine will not do any more actions anymore.
    #[action]
    #[allow(unused_variables)]
    pub(crate) async fn on_closed_entry(&mut self, context: &mut StateContext<T>) {
        self.matchers.clear();
    }

    #[state(entry_action = "on_closed_entry")]
    // Terminal state when the kickoff process ends
    #[allow(unused_variables)]
    pub(crate) async fn closed(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        Handled
    }
}
