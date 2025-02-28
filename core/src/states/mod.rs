use crate::builder::transaction::{
    ContractContext, DepositData, OperatorData, TransactionType, TxHandler,
};
use crate::config::protocol::ProtocolParamset;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::KickoffId;
use bitcoin::hashes::hash160::Hash;
use bitcoin::{Block, OutPoint, Transaction, Txid};
use futures::future::{join, join_all};
use futures::TryFuture;
use statig::awaitable::InitializedStateMachine;
use statig::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;
use tonic::async_trait;

trait BlockMatcher {
    type Event;

    fn match_block(&self, block: &BlockCache) -> Vec<Self::Event>;
}

mod kickoff;
mod round;

// Block cache to optimize lookups
#[derive(Debug, Clone, Default)]
pub struct BlockCache {
    txids: HashMap<Txid, Transaction>,
    spent_utxos: HashSet<OutPoint>,
}

impl BlockCache {
    pub fn new() -> Self {
        Self {
            txids: HashMap::new(),
            spent_utxos: HashSet::new(),
        }
    }

    pub fn update_with_block(&mut self, block: &Block) {
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
}

impl Matcher {
    pub fn matches(&self, block: &BlockCache) -> bool {
        match self {
            Matcher::SentTx(txid) => block.contains_txid(txid),
            Matcher::SpentUtxo(outpoint) => block.is_utxo_spent(outpoint),
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
}

// DutyHandler trait with async handling
#[async_trait]
pub trait Owner: Send + Sync + Clone + Default {
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

impl<T: Owner> StateManager<T> {
    pub fn new(db: Database, handler: T, paramset: &'static ProtocolParamset) -> Self {
        Self {
            round_machines: Vec::new(),
            kickoff_machines: Vec::new(),
            context: StateContext::new(
                db.clone(),
                Arc::new(handler.clone()),
                Default::default(),
                paramset,
            ),
            db,
            owner: handler,
            paramset,
        }
    }

    pub async fn add_kickoff_machine(
        &mut self,
        kickoff_id: crate::rpc::clementine::KickoffId,
    ) -> Result<(), BridgeError> {
        let machine = kickoff::KickoffStateMachine::<T>::new(kickoff_id);
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

    pub async fn process_block_parallel(&mut self, block: &Block) -> Result<(), BridgeError> {
        let mut cache: BlockCache = Default::default();
        cache.update_with_block(block);

        // Create a base context with updated cache
        let base_context =
            Self::create_context(self.owner.clone(), self.db.clone(), cache, self.paramset);

        // Collect all machines and their events first to avoid borrowing issues
        let kickoff_futures = (self.kickoff_machines).iter_mut().filter_map(|machine| {
            let events = machine.match_block(&base_context.cache);
            if !events.is_empty() {
                let mut ctx = base_context.clone();
                Some(async move {
                    for event in events {
                        machine.handle_with_context(&event, &mut ctx).await;
                    }
                    ctx
                })
            } else {
                None
            }
        });

        let round_futures = (self.round_machines).iter_mut().filter_map(|machine| {
            let events = machine.match_block(&base_context.cache);
            if !events.is_empty() {
                let mut ctx = base_context.clone();
                Some(async move {
                    for event in events {
                        machine.handle_with_context(&event, &mut ctx).await;
                    }
                    ctx
                })
            } else {
                None
            }
        });

        // Execute all futures
        let (kickoff_results, round_results) =
            join(join_all(kickoff_futures), join_all(round_futures)).await;

        // Merge contexts
        let mut all_contexts = Vec::new();
        all_contexts.extend(kickoff_results);
        all_contexts.extend(round_results);

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

        // Collect new machines from all contexts
        let mut final_context = base_context;
        for ctx in &mut all_contexts {
            final_context
                .new_kickoff_machines
                .extend(std::mem::take(&mut ctx.new_kickoff_machines));
            final_context
                .new_round_machines
                .extend(std::mem::take(&mut ctx.new_round_machines));
        }

        // TODO: commit to db

        // Commit new machines - moved out of the borrow region
        self.round_machines
            .extend(std::mem::take(&mut final_context.new_round_machines));
        self.kickoff_machines
            .extend(std::mem::take(&mut final_context.new_kickoff_machines));

        Ok(())
    }
}
