use std::collections::HashMap;

use bitcoin::OutPoint;
use statig::prelude::*;

use crate::{
    builder::transaction::{ContractContext, DepositData, TransactionType},
    errors::BridgeError,
    rpc::clementine::KickoffId,
    states::Duty,
};

use super::{BlockCache, BlockMatcher, Matcher, Owner, StateContext};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KickoffEvent {
    Challenged,
    WatchtowerChallengeSent,
    OperatorAssertSent,
    KickoffFinalizerSpent,
    BurnConnectorSpent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KickoffStateMachine<T: Owner> {
    pub(crate) matchers: HashMap<Matcher, KickoffEvent>,
    pub(crate) dirty: bool,
    kickoff_id: KickoffId,
    num_operators: u32,
    num_watchtowers: u32,
    deposit_data: DepositData,
    kickoff_height: u32,
    watchtower_challenges: HashMap<u32, Vec<u8>>,
    operator_asserts: HashMap<u32, Vec<u8>>,
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
        num_operators: u32,
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
            num_operators,
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
        let kickoff_txhandler = txhandlers
            .remove(&TransactionType::Kickoff)
            .ok_or(BridgeError::TxHandlerNotFound(TransactionType::Kickoff))?;
        // add operator asserts
        let kickoff_txid = kickoff_txhandler.get_txid();
        for idx in 4..4 + self.num_operators {
            let matcher = Matcher::SpentUtxo(OutPoint {
                txid: *kickoff_txid,
                vout: idx,
            });
            self.matchers
                .insert(matcher, KickoffEvent::OperatorAssertSent);
        }
        // add watchtower challenges
        for idx in 4 + self.num_operators..4 + self.num_operators + self.num_watchtowers {
            let matcher = Matcher::SpentUtxo(OutPoint {
                txid: *kickoff_txid,
                vout: idx,
            });
            self.matchers
                .insert(matcher, KickoffEvent::WatchtowerChallengeSent);
        }
        // add challenge tx
        Ok(())
    }

    #[action]
    pub(crate) async fn on_kickoff_started_entry(&mut self, context: &mut StateContext<T>) {
        println!("Kickoff Started");
        context
            .capture_error(async |context| context.dispatch_duty(Duty::NewKickoff).await)
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
            .capture_error(async |context| context.dispatch_duty(Duty::WatchtowerChallenge).await)
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
            .capture_error(async |context| context.dispatch_duty(Duty::OperatorAssert).await)
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
            .capture_error(async |context| context.dispatch_duty(Duty::VerifierDisprove).await)
            .await;
    }
}
