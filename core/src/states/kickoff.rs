use std::collections::HashMap;

use statig::prelude::*;

use crate::{rpc::clementine::KickoffId, states::Duty};

use super::{BlockCache, BlockMatcher, Matcher, Owner, StateContext};

#[derive(Debug, Clone)]
pub enum KickoffEvent {
    TBD,
}

#[derive(Debug, Clone)]
enum KickoffMatcher {
    TBD,
}

impl KickoffMatcher {
    fn get_event(&self, _matcher: Matcher) -> KickoffEvent {
        match self {
            KickoffMatcher::TBD => KickoffEvent::TBD,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KickoffStateMachine<T: Owner> {
    pub(crate) kickoff_id: KickoffId,
    pub(crate) matchers: HashMap<Matcher, KickoffMatcher>,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Owner> BlockMatcher for KickoffStateMachine<T> {
    type Event = KickoffEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::Event> {
        self.matchers
            .iter()
            .filter_map(|(matcher, kickoff_matcher)| {
                if matcher.matches(block) {
                    Some(kickoff_matcher.get_event(matcher.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<T: Owner> KickoffStateMachine<T> {
    pub fn new(kickoff_id: KickoffId) -> Self {
        Self {
            kickoff_id,
            matchers: HashMap::new(),
            phantom: std::marker::PhantomData,
        }
    }
}

#[state_machine(initial = "State::idle()", state(derive(Debug, Clone)))]
impl<T: Owner> KickoffStateMachine<T> {
    // Kickoff process state handlers

    #[state]
    pub(crate) async fn idle(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[state(entry_action = "on_kickoff_started_entry")]
    pub(crate) async fn kickoff_started(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_kickoff_started_entry(&mut self, context: &mut StateContext<T>) {
        println!("Kickoff Started");
        context
            .try_run(async |context| context.dispatch_duty(Duty::NewKickoff).await)
            .await;
    }

    #[state(entry_action = "on_watchtower_challenge_entry")]
    pub(crate) async fn watchtower_to_challenge(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_watchtower_challenge_entry(&mut self, context: &mut StateContext<T>) {
        println!("Watchtower Challenge Stage");
        context
            .try_run(async |context| context.dispatch_duty(Duty::WatchtowerChallenge).await)
            .await;
    }

    #[state(entry_action = "on_operator_assert_entry")]
    pub(crate) async fn operator_to_assert(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_operator_assert_entry(&mut self, context: &mut StateContext<T>) {
        println!("Operator Assert Stage");
        context
            .try_run(async |context| context.dispatch_duty(Duty::OperatorAssert).await)
            .await;
    }

    #[state(entry_action = "on_verifier_disprove_entry")]
    pub(crate) async fn verifier_to_disprove(
        &mut self,
        event: &KickoffEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_verifier_disprove_entry(&mut self, context: &mut StateContext<T>) {
        println!("Verifier Disprove Stage");
        context
            .try_run(async |context| context.dispatch_duty(Duty::VerifierDisprove).await)
            .await;
    }
}
