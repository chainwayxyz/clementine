use std::collections::HashMap;

use bitcoin::{OutPoint, Txid, Witness};
use statig::prelude::*;

use crate::{
    builder::transaction::{
        remove_txhandler_from_map, ContractContext, DepositData, TransactionType,
    },
    errors::BridgeError,
    rpc::clementine::KickoffId,
    states::Duty,
    utils,
};

use super::{BlockCache, BlockMatcher, Matcher, Owner, StateContext};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KickoffStateMachine<T: Owner> {
    pub(crate) matchers: HashMap<Matcher, KickoffEvent>,
    pub(crate) dirty: bool,
    kickoff_id: KickoffId,
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
            dirty: false,
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
    on_transition = "Self::on_transition",
    state(derive(Debug, Clone))
)]
impl<T: Owner> KickoffStateMachine<T> {
    #[action]
    pub(crate) fn on_transition(&mut self, state_a: &State, state_b: &State) {
        tracing::debug!(?self.kickoff_id, "Transitioning from {:?} to {:?}", state_a, state_b);
        self.dirty = true;
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
        let kickoff_txid = kickoff_txhandler.get_txid();
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
            let matcher = Matcher::SpentUtxo(OutPoint {
                txid: *kickoff_txid,
                vout: mini_assert_vout as u32,
            });
            self.matchers.insert(
                matcher,
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
            let matcher = Matcher::SpentUtxo(OutPoint {
                txid: *kickoff_txid,
                vout: watchtower_challenge_vout as u32,
            });
            self.matchers.insert(
                matcher,
                KickoffEvent::WatchtowerChallengeSent {
                    watchtower_idx,
                    challenge_txid: watchtower_challenge_txid,
                },
            );
        }
        // add challenge tx
        Ok(())
    }

    #[action]
    pub(crate) async fn on_kickoff_started_entry(&mut self, context: &mut StateContext<T>) {
        println!("Kickoff Started");
        context
            .capture_error(async |context| {
                // Add all watchtower challenges and operator asserts to matchers
                self.add_default_matchers(context).await?;
                Ok(())
            })
            .await;
    }

    #[state(entry_action = "on_challenge_entry")]
    pub(crate) async fn challenged(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_challenge_entry(&mut self, context: &mut StateContext<T>) {
        println!("Watchtower Challenge Stage");
        context
            .capture_error(async |context| context.dispatch_duty(Duty::WatchtowerChallenge).await)
            .await;
    }
}
