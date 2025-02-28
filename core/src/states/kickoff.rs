use std::collections::HashMap;

use bitcoin::{OutPoint, Txid, Witness};
use eyre::Report;
use statig::prelude::*;

use crate::{
    builder::transaction::{
        remove_txhandler_from_map, ContractContext, DepositData, TransactionType,
    },
    errors::BridgeError,
    rpc::clementine::KickoffId,
    utils,
};

use super::{
    block_cache::BlockCache,
    context::StateContext,
    matcher::{BlockMatcher, Matcher},
    Owner,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KickoffEvent {
    Challenged,
    WatchtowerChallengeSent {
        watchtower_idx: u32,
        challenge_txid: Txid,
    },
    OperatorAssertSent {
        assert_idx: u32,
        assert_txid: Txid,
    },
    KickoffFinalizerSpent,
    BurnConnectorSpent,
    TimeToSendWatchtowerChallenge,
    TimeToSendOperatorAssert,
    TimeToSendVerifierDisprove,
    /// Special event that is used to indicate that the state machine has been saved to the database and the dirty flag should be reset
    SavedToDb,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
// TODO: add and save operator challenge acks
// save watchtower challenge utxo's spending (not only challenge, also timeout)
// all timelocks
// delete used matchers?
pub struct KickoffStateMachine<T: Owner> {
    pub(crate) matchers: HashMap<Matcher, KickoffEvent>,
    pub(crate) dirty: bool,
    pub(crate) kickoff_id: KickoffId,
    num_watchtowers: u32,
    deposit_data: DepositData,
    kickoff_height: u32,
    watchtower_challenges: HashMap<u32, Witness>,
    operator_asserts: HashMap<u32, Witness>,
    watchtower_challenge_sent: bool,
    operator_assert_sent: bool,
    verifier_disprove_sent: bool,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Owner> BlockMatcher for KickoffStateMachine<T> {
    type StateEvent = KickoffEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::StateEvent> {
        self.matchers
            .iter()
            .filter_map(|(matcher, kickoff_event)| {
                if matcher.matches(block) {
                    Some(kickoff_event.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<T: Owner> KickoffStateMachine<T> {
    // TODO: num_operators and num_watchtowers in deposit_data in the future
    pub fn new(
        kickoff_id: KickoffId,
        kickoff_height: u32,
        deposit_data: DepositData,
        num_watchtowers: u32,
    ) -> Self {
        Self {
            kickoff_id,
            kickoff_height,
            deposit_data,
            matchers: HashMap::new(),
            dirty: true,
            phantom: std::marker::PhantomData,
            watchtower_challenges: HashMap::new(),
            operator_asserts: HashMap::new(),
            watchtower_challenge_sent: false,
            operator_assert_sent: false,
            verifier_disprove_sent: false,
            num_watchtowers,
        }
    }
}

#[state_machine(
    initial = "State::kickoff_started()",
    on_dispatch = "Self::on_dispatch",
    state(derive(Debug, Clone, serde::Serialize, serde::Deserialize))
)]
impl<T: Owner> KickoffStateMachine<T> {
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
        }
    }

    #[state(entry_action = "on_kickoff_started_entry")]
    pub(crate) async fn kickoff_started(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            KickoffEvent::WatchtowerChallengeSent {
                watchtower_idx,
                challenge_txid,
            } => {
                let tx = context
                    .cache
                    .txids
                    .get(challenge_txid)
                    .expect("Watchtower txid that got matched should be in cache");
                // save challenge witness
                self.watchtower_challenges
                    .insert(*watchtower_idx, tx.input[0].witness.clone());
                Handled
            }
            KickoffEvent::OperatorAssertSent {
                assert_idx,
                assert_txid,
            } => {
                let tx = context
                    .cache
                    .txids
                    .get(assert_txid)
                    .expect("Assert txid that got matched should be in cache");
                // save assert witness
                self.operator_asserts
                    .insert(*assert_idx, tx.input[0].witness.clone());
                Handled
            }
            KickoffEvent::BurnConnectorSpent | KickoffEvent::KickoffFinalizerSpent => {
                Transition(State::closed())
            }
            _ => Super,
        }
    }

    async fn add_default_matchers(
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
            .create_txhandlers(TransactionType::Kickoff, contract_context)
            .await?;
        let kickoff_txhandler =
            remove_txhandler_from_map(&mut txhandlers, TransactionType::Kickoff)?;

        // add operator asserts
        let kickoff_txid = *kickoff_txhandler.get_txid();
        let num_asserts = utils::COMBINED_ASSERT_DATA.num_steps.len();
        for assert_idx in 0..num_asserts {
            // TODO: use dedicated functions or smth else, not hardcoded here.
            // It will be easier when we have data of operators/watchtowers that participated in the deposit in DepositData
            let mini_assert_vout = 4 + assert_idx;
            let operator_assert_txid = *remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::MiniAssert(assert_idx),
            )?
            .get_txid();
            self.matchers.insert(
                Matcher::SpentUtxo(OutPoint {
                    txid: kickoff_txid,
                    vout: mini_assert_vout as u32,
                }),
                KickoffEvent::OperatorAssertSent {
                    assert_txid: operator_assert_txid,
                    assert_idx: assert_idx as u32,
                },
            );
        }
        // add watchtower challenges
        for watchtower_idx in 0..self.num_watchtowers {
            // TODO: use dedicated functions or smth else, not hardcoded here.
            // It will be easier when we have data of operators/watchtowers that participated in the deposit in DepositData
            let watchtower_challenge_vout = 4 + num_asserts + watchtower_idx as usize * 2;
            let watchtower_challenge_txid = *remove_txhandler_from_map(
                &mut txhandlers,
                TransactionType::WatchtowerChallenge(watchtower_idx as usize),
            )?
            .get_txid();
            self.matchers.insert(
                Matcher::SpentUtxo(OutPoint {
                    txid: kickoff_txid,
                    vout: watchtower_challenge_vout as u32,
                }),
                KickoffEvent::WatchtowerChallengeSent {
                    watchtower_idx,
                    challenge_txid: watchtower_challenge_txid,
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
        // create times to send necessary asserts
        Ok(())
    }

    #[action]
    pub(crate) async fn on_kickoff_started_entry(&mut self, context: &mut StateContext<T>) {
        println!("Kickoff Started");
        context
            .capture_error(async |context| {
                {
                    // Add all watchtower challenges and operator asserts to matchers
                    self.add_default_matchers(context).await?;
                    Ok(())
                }
                .map_err(self.wrap_err("on_kickoff_started_entry"))
            })
            .await;
    }

    #[state(entry_action = "on_closed_entry")]
    // Terminal state
    pub(crate) async fn closed(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        Handled
    }

    #[action]
    pub(crate) async fn on_closed_entry(&mut self, context: &mut StateContext<T>) {
        self.matchers.clear();
    }
}
