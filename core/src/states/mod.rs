use crate::builder::transaction::{
    ContractContext, DepositData, OperatorData, TransactionType, TxHandler,
};
use crate::config::protocol::ProtocolParamset;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::KickoffId;
use bitcoin::hashes::hash160::Hash;
use bitcoin::secp256k1::Context;
use bitcoin::{Block, OutPoint, Transaction, Txid};
use futures::future::{self, join, join_all, Map};
use futures::{FutureExt, TryFuture};
use statig::awaitable::InitializedStateMachine;
use statig::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;
use tonic::async_trait;

trait BlockMatcher {
    type StateEvent;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::StateEvent>;
}

enum ContextProcessResult<
    T: Owner,
    M: IntoStateMachine,
    Fut: Future<Output = (InitializedStateMachine<M>, StateContext<T>)> + Send,
> {
    Unchanged(InitializedStateMachine<M>),
    Processing(Fut),
}

/// Utility trait to make a generic process_block function
trait ContextProcessor<T: Owner, M: IntoStateMachine> {
    fn process_with_ctx(
        self,
        block: &StateContext<T>,
    ) -> ContextProcessResult<
        T,
        M,
        impl Future<Output = (InitializedStateMachine<M>, StateContext<T>)> + Send,
    >;
}

impl<T, M> ContextProcessor<T, M> for InitializedStateMachine<M>
where
    T: Owner,
    for<'evt, 'ctx> M: IntoStateMachine<Event<'evt> = M::StateEvent, Context<'ctx> = StateContext<T>>
        + Send
        + BlockMatcher,
    M::State: awaitable::State<M> + 'static + Send,
    for<'sub> M::Superstate<'sub>: awaitable::Superstate<M> + Send,
    for<'evt> M::Event<'evt>: Send + Sync,
{
    fn process_with_ctx(
        mut self,
        block: &StateContext<T>,
    ) -> ContextProcessResult<T, M, impl Future<Output = (Self, StateContext<T>)> + Send> {
        let events = self.match_block(&block.cache);
        if events.is_empty() {
            ContextProcessResult::Unchanged(self)
        } else {
            let mut ctx = block.clone();
            ContextProcessResult::Processing(async move {
                for event in events {
                    self.handle_with_context(&event, &mut ctx).await;
                }
                (self, ctx)
            })
        }
    }
}

mod kickoff;
mod round;

// Block cache to optimize lookups
#[derive(Debug, Clone, Default)]
pub struct BlockCache {
    txids: HashMap<Txid, Transaction>,
    spent_utxos: HashSet<OutPoint>,
    block_height: u32,
}

impl BlockCache {
    pub fn new() -> Self {
        Self {
            txids: HashMap::new(),
            spent_utxos: HashSet::new(),
            block_height: 0,
        }
    }

    pub fn update_with_block(&mut self, block: &Block, block_height: u32) {
        self.block_height = block_height;
        for tx in &block.txdata {
            self.txids.insert(tx.compute_txid(), tx.clone());

            // Mark UTXOs as spent
            for input in &tx.input {
                self.spent_utxos.insert(input.previous_output);
            }
        }
    }

    pub fn contains_txid(&self, txid: &Txid) -> bool {
        self.txids.contains_key(txid)
    }

    pub fn is_utxo_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_utxos.contains(outpoint)
    }
}

// Matcher for state machines to define what they're interested in
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Matcher {
    SentTx(Txid),
    SpentUtxo(OutPoint),
    BlockHeight(u32),
}

impl Matcher {
    pub fn matches(&self, block: &BlockCache) -> bool {
        match self {
            Matcher::SentTx(txid) => block.contains_txid(txid),
            Matcher::SpentUtxo(outpoint) => block.is_utxo_spent(outpoint),
            Matcher::BlockHeight(height) => *height == block.block_height,
        }
    }
}

// Duty types that can be dispatched
#[derive(Debug, Clone)]
pub enum Duty {
    NewKickoff,
    NewReadyToReimburse {
        round_idx: u32,
        operator_idx: u32,
        used_kickoffs: HashSet<usize>,
    },
    WatchtowerChallenge,
    OperatorAssert,
    VerifierDisprove,
    CheckIfMalicious,
}

/// Owner trait with async handling and tx handler creation
#[async_trait]
pub trait Owner: Send + Sync + Clone + Default {
    /// Handle a duty
    async fn handle_duty(&self, duty: Duty) -> Result<(), BridgeError>;
    async fn create_txhandlers(
        &self,
        tx_type: TransactionType,
        contract_context: ContractContext,
    ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError>;
}

// Enhanced StateError enum
#[derive(Error, Debug)]
pub enum StateError {
    #[error("State machine error in {state_name} during {action}: {source}")]
    StateMachineError {
        state_name: String,
        action: String,
        source: BridgeError,
    },
    #[error("Context error: {0}")]
    ContextError(String),
    #[error("Multiple errors: {0:?}")]
    MultipleErrors(Vec<Arc<StateError>>),
}

#[derive(Debug, Clone)]
pub struct StateContext<T: Owner> {
    pub db: Database,
    pub owner: Arc<T>,
    pub cache: Arc<BlockCache>,
    pub new_round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    pub new_kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    pub errors: Vec<Arc<StateError>>,
    pub current_state: Option<String>,
    pub current_action: Option<String>,
    pub paramset: &'static ProtocolParamset,
}

impl<T: Owner> StateContext<T> {
    pub fn new(
        db: Database,
        owner: Arc<T>,
        cache: Arc<BlockCache>,
        paramset: &'static ProtocolParamset,
    ) -> Self {
        Self {
            db,
            owner,
            cache,
            new_round_machines: Vec::new(),
            new_kickoff_machines: Vec::new(),
            errors: Vec::new(),
            current_state: None,
            current_action: None,
            paramset,
        }
    }

    // Method to set the current state and action context
    pub fn set_state_info(&mut self, state: impl Into<String>, action: impl Into<String>) {
        self.current_state = Some(state.into());
        self.current_action = Some(action.into());
    }

    pub async fn dispatch_duty(&self, duty: Duty) -> Result<(), BridgeError> {
        self.owner.handle_duty(duty).await
    }

    pub fn add_new_round_machine(
        &mut self,
        machine: InitializedStateMachine<round::RoundStateMachine<T>>,
    ) {
        self.new_round_machines.push(machine);
    }

    pub fn add_new_kickoff_machine(
        &mut self,
        machine: InitializedStateMachine<kickoff::KickoffStateMachine<T>>,
    ) {
        self.new_kickoff_machines.push(machine);
    }

    // Enhanced try_run method for better error context
    pub async fn capture_error(
        &mut self,
        fnc: impl AsyncFnOnce(&mut Self) -> Result<(), BridgeError>,
    ) {
        let result = fnc(self).await;
        if let Err(e) = result {
            let state_error = match (&self.current_state, &self.current_action) {
                (Some(state), Some(action)) => Arc::new(StateError::StateMachineError {
                    state_name: state.clone(),
                    action: action.clone(),
                    source: e,
                }),
                _ => Arc::new(StateError::ContextError(e.to_string())),
            };
            self.errors.push(state_error);
        }
    }
}

// New state manager to hold and coordinate state machines
#[derive(Debug)]
pub struct StateManager<T: Owner> {
    db: Database,
    owner: T,
    round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    context: StateContext<T>,
    paramset: &'static ProtocolParamset,
}

impl<T: Owner + 'static> StateManager<T> {
    pub fn new(db: Database, handler: T, paramset: &'static ProtocolParamset) -> Self {
        Self {
            context: StateContext::new(
                db.clone(),
                Arc::new(handler.clone()),
                Default::default(),
                paramset,
            ),
            db,
            owner: handler,
            paramset,
            round_machines: Vec::new(),
            kickoff_machines: Vec::new(),
        }
    }

    pub async fn add_kickoff_machine(
        &mut self,
        kickoff_id: crate::rpc::clementine::KickoffId,
        block_height: u32,
        deposit_data: DepositData,
    ) -> Result<(), BridgeError> {
        let machine =
            kickoff::KickoffStateMachine::<T>::new(kickoff_id, block_height, deposit_data);
        let initialized_machine = machine
            .uninitialized_state_machine()
            .init_with_context(&mut self.context)
            .await;

        self.kickoff_machines.push(initialized_machine);
        Ok(())
    }

    pub async fn add_round_machine(
        &mut self,
        operator_data: OperatorData,
        operator_idx: u32,
    ) -> Result<(), BridgeError> {
        let machine = round::RoundStateMachine::<T>::new(operator_data, operator_idx);
        let initialized_machine = machine
            .uninitialized_state_machine()
            .init_with_context(&mut self.context)
            .await;

        self.round_machines.push(initialized_machine);
        Ok(())
    }

    fn create_context(
        handler: T,
        db: Database,
        cache: BlockCache,
        paramset: &'static ProtocolParamset,
    ) -> StateContext<T> {
        StateContext {
            db: db.clone(),
            owner: Arc::new(handler),
            cache: Arc::new(cache),
            new_kickoff_machines: Vec::new(),
            new_round_machines: Vec::new(),
            errors: Vec::new(),
            current_state: None,
            current_action: None,
            paramset,
        }
    }

    pub fn update_machines<'a, M>(
        machines: &mut Vec<InitializedStateMachine<M>>,
        base_context: &'a StateContext<T>,
    ) -> (
        Vec<InitializedStateMachine<M>>,
        Vec<impl Future<Output = (InitializedStateMachine<M>, StateContext<T>)> + Send + 'a>,
    )
    where
        M: IntoStateMachine + Send + Sync + 'static,
        M::State: Send + Sync + 'static,
        InitializedStateMachine<M>: ContextProcessor<T, M>,
    {
        let mut new_machines = Vec::new();
        let mut processing_futures = Vec::new();

        for machine in std::mem::take(machines).into_iter() {
            match machine.process_with_ctx(&base_context) {
                ContextProcessResult::Processing(future) => processing_futures.push(future),
                ContextProcessResult::Unchanged(machine) => new_machines.push(machine),
            }
        }

        (new_machines, processing_futures)
    }

    pub async fn process_block_parallel(&mut self, block: &Block,         block_height: u32) -> Result<(), BridgeError> {
        let mut cache: BlockCache = Default::default();
        cache.update_with_block(block, block_height);

        let base_context =
            Self::create_context(self.owner.clone(), self.db.clone(), cache, self.paramset);

        // Process all machines, for those unaffected return them, otherwise return
        // a future that processes the new events.
        let (mut final_kickoff_machines, mut kickoff_futures) =
            Self::update_machines(&mut self.kickoff_machines, &base_context);
        let (mut final_round_machines, mut round_futures) =
            Self::update_machines(&mut self.round_machines, &base_context);

        // On each iteration, we'll update the changed machines until all machines
        // stabilize in their state.
        while !kickoff_futures.is_empty() || !round_futures.is_empty() {
            // Execute all futures in parallel
            let (kickoff_results, round_results) =
                join(join_all(kickoff_futures), join_all(round_futures)).await;

            // Unzip the results into updated machines and state contexts
            let (mut changed_kickoff_machines, kickoff_contexts): (Vec<_>, Vec<_>) =
                kickoff_results.into_iter().unzip();
            let (mut changed_round_machines, round_contexts): (Vec<_>, Vec<_>) =
                round_results.into_iter().unzip();

            // Merge contexts
            let mut all_contexts: Vec<StateContext<T>> = Vec::new();
            all_contexts.extend(kickoff_contexts);
            all_contexts.extend(round_contexts);

            // Merge and handle errors
            let mut all_errors = Vec::new();
            for ctx in &mut all_contexts {
                all_errors.extend(std::mem::take(&mut ctx.errors));
            }

            if !all_errors.is_empty() {
                // Return first error or create a combined error
                return Err(BridgeError::Error(
                    "Multiple errors occurred during state processing".into(),
                ));
            }

            // Append the newly generated state machines into the changed machines list
            for ctx in &mut all_contexts {
                changed_round_machines.extend(std::mem::take(&mut ctx.new_round_machines));
                changed_kickoff_machines.extend(std::mem::take(&mut ctx.new_kickoff_machines));
            }

            // Reprocess changed machines and commit these futures to be handled
            // in the next round If they're empty, we'll exit the loop.
            let (finalized_kickoff_machines, new_kickoff_futures) =
                Self::update_machines(&mut changed_kickoff_machines, &base_context);
            let (finalized_round_machines, new_round_futures) =
                Self::update_machines(&mut changed_round_machines, &base_context);
            final_kickoff_machines.extend(finalized_kickoff_machines);
            final_round_machines.extend(finalized_round_machines);

            kickoff_futures = new_kickoff_futures;
            round_futures = new_round_futures;
        }

        // TODO: commit to db

        // Add back the original machines
        self.round_machines.extend(final_round_machines);
        self.kickoff_machines.extend(final_kickoff_machines);

        // Commit new machines - moved out of the borrow region

        Ok(())
    }
}
