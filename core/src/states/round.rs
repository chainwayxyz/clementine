use std::collections::HashMap;

use statig::prelude::*;

use crate::{builder::transaction::OperatorData, rpc::clementine::KickoffId, states::Duty};

use super::{BlockCache, BlockMatcher, Matcher, Owner, StateContext};

#[derive(Debug, Clone)]
pub enum RoundEvent {
    KickoffSent(KickoffId),
    ReadyToReimburseSent { round_idx: u32 },
    RoundSent { round_idx: u32 },
}

#[derive(Debug, Clone)]
pub(crate) enum RoundMatcher {
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
pub struct RoundStateMachine<T: Owner> {
    pub(crate) matchers: HashMap<Matcher, RoundMatcher>,
    operator_data: OperatorData,
    operator_idx: u32,
    pub(crate) dirty: bool,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Owner> BlockMatcher for RoundStateMachine<T> {
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

#[state_machine(
    initial = "State::initial_collateral()",
    on_transition = "Self::on_transition",
    state(derive(Debug, Clone))
)]
impl<T: Owner> RoundStateMachine<T> {
    #[action]
    pub(crate) fn on_transition(&mut self, state_a: &State, state_b: &State) {
        tracing::debug!("Transitioning from {:?} to {:?}", state_a, state_b);
        self.dirty = true;
    }

    #[state(entry_action = "on_initial_collateral_entry")]
    pub(crate) async fn initial_collateral(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            RoundEvent::RoundSent { round_idx } => Transition(State::round_tx(*round_idx)),
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_initial_collateral_entry(&mut self, context: &mut StateContext<T>) {
        self.matchers = HashMap::new();
        self.matchers.insert(
            Matcher::SpentUtxo(self.operator_data.collateral_funding_outpoint),
            RoundMatcher::RoundSent { round_idx: 0 },
        );
    }

    #[state(entry_action = "on_round_tx_entry")]
    pub(crate) async fn round_tx(
        &mut self,
        event: &RoundEvent,
        round_idx: &mut u32,
        context: &mut StateContext<T>,
    ) -> Response<State> {
        match event {
            RoundEvent::ReadyToReimburseSent { round_idx } => {
                Transition(State::ready_to_reimburse(*round_idx))
            }
            _ => Super,
        }
    }

    #[action]
    pub(crate) async fn on_round_tx_entry(
        &mut self,
        round_idx: &mut u32,
        context: &mut StateContext<T>,
    ) {
        println!("Entered Round Tx state");
        self.matchers = HashMap::new();
        let x = context.owner.create_txhandlers();
    }

    #[state(entry_action = "on_ready_to_reimburse_entry")]
    pub(crate) async fn ready_to_reimburse(
        &mut self,
        event: &RoundEvent,
        context: &mut StateContext<T>,
        round_idx: &mut u32,
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
