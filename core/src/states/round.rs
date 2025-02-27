use std::collections::HashMap;

use statig::prelude::*;

use crate::{rpc::clementine::KickoffId, states::Duty};

use super::{BlockCache, BlockMatcher, DutyHandler, Matcher, StateContext};

#[derive(Debug, Clone)]
pub enum RoundEvent {
    KickoffSent(KickoffId),
    ReadyToReimburseSent { round_idx: u32 },
    RoundSent { round_idx: u32 },
}

#[derive(Debug, Clone)]
enum RoundMatcher {
    KickoffSent(KickoffId),
    ReadyToReimburseSent { round_idx: u32 },
    RoundSent { round_idx: u32 },
}

impl RoundMatcher {
    fn get_event(&self, matcher: Matcher) -> RoundEvent {
        match self {
            RoundMatcher::KickoffSent(kickoff_id) => RoundEvent::KickoffSent(*kickoff_id),
            RoundMatcher::ReadyToReimburseSent { round_idx } => RoundEvent::ReadyToReimburseSent {
                round_idx: *round_idx,
            },
            RoundMatcher::RoundSent { round_idx } => RoundEvent::RoundSent {
                round_idx: *round_idx,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoundStateMachine<T: DutyHandler> {
    pub(crate) matchers: HashMap<Matcher, RoundMatcher>,
    phantom: std::marker::PhantomData<T>,
}

impl<T: DutyHandler> BlockMatcher for RoundStateMachine<T> {
    type Event = RoundEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::Event> {
        self.matchers
            .iter()
            .filter_map(|(matcher, round_matcher)| {
                if matcher.matches(block) {
                    Some(round_matcher.get_event(matcher.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<T: DutyHandler> RoundStateMachine<T> {
    pub fn new() -> Self {
        Self {
            matchers: HashMap::new(),
            phantom: std::marker::PhantomData,
        }
    }
}

#[state_machine(initial = "State::initial_collateral()", state(derive(Debug, Clone)))]
impl<T: DutyHandler> RoundStateMachine<T> {
    // State handlers with proper statig approach

    #[state(entry_action = "on_initial_collateral_entry")]
    pub(crate) async fn initial_collateral(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_initial_collateral_entry(&mut self, context: &mut StateContext<T>) {
        println!("Entered Initial Collateral state");
    }

    #[state(entry_action = "on_round_tx_entry")]
    pub(crate) async fn round_tx(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_round_tx_entry(&mut self, context: &mut StateContext<T>) {
        println!("Entered Round Tx state");
        // Assuming context.dispatch_duty is called elsewhere in the code
    }

    #[state(entry_action = "on_ready_to_reimburse_entry")]
    pub(crate) async fn ready_to_reimburse(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_ready_to_reimburse_entry(&mut self, context: &mut StateContext<T>) {
        println!("Entered Ready To Reimburse state");
    }
}
