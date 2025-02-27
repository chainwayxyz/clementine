use crate::builder::transaction::{OperatorData, TransactionType, TxHandler};
use crate::config::protocol::ProtocolParamset;
use crate::database::Database;
use crate::errors::BridgeError;
use bitcoin::{Block, OutPoint, Transaction, Txid};
use futures::TryFuture;
use statig::awaitable::InitializedStateMachine;
use statig::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
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
    NewRound,
    WatchtowerChallenge,
    OperatorAssert,
    VerifierDisprove,
}

// DutyHandler trait with async handling
#[async_trait]
pub trait Owner: Send + Sync + Clone + Default {
    async fn handle_duty(&self, duty: Duty) -> Result<(), BridgeError>;
    async fn create_txhandlers(&self) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError>;
}

// Context shared between state machines
#[derive(Debug, Clone)]
pub struct StateContext<T: Owner> {
    pub db: Database,
    pub owner: T,
    pub cache: BlockCache,
    pub new_round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    pub new_kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    pub errors: Vec<Arc<BridgeError>>,
    pub paramset: &'static ProtocolParamset,
}

impl<T: Owner> StateContext<T> {
    pub fn new(db: Database, owner: T, paramset: &'static ProtocolParamset) -> Self {
        Self {
            db,
            owner,
            cache: BlockCache::new(),
            new_round_machines: Vec::new(),
            new_kickoff_machines: Vec::new(),
            errors: Vec::new(),
            paramset,
        }
    }

    pub async fn dispatch_duty(&self, duty: Duty) -> Result<(), BridgeError> {
        self.owner.handle_duty(duty).await
    }

    pub fn update_cache(&mut self, block: &Block) {
        self.cache.update_with_block(block);
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

    pub async fn try_run<Func: AsyncFnOnce(&mut Self) -> Result<(), BridgeError>>(
        &mut self,
        fnc: Func,
    ) {
        let result = fnc(self).await;
        if let Err(e) = result {
            self.errors.push(Arc::new(e));
        }
    }
}

// New state manager to hold and coordinate state machines
#[derive(Debug)]
pub struct StateManager<T: Owner> {
    db: Database,
    handler: T,
    round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    cache: BlockCache,
    paramset: &'static ProtocolParamset,
    context: StateContext<T>,
}

impl<T: Owner> StateManager<T> {
    pub fn new(db: Database, handler: T, paramset: &'static ProtocolParamset) -> Self {
        Self {
            round_machines: Vec::new(),
            kickoff_machines: Vec::new(),
            cache: BlockCache::new(),
            context: StateContext::new(db.clone(), handler.clone(), paramset),
            db,
            paramset,
            handler,
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

    fn create_context(&self) -> StateContext<T> {
        StateContext {
            db: self.db.clone(),
            owner: self.handler.clone(),
            cache: self.cache.clone(),
            paramset: self.paramset,
            new_kickoff_machines: Vec::new(),
            new_round_machines: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub async fn process_block(&mut self, block: &Block) -> Result<(), BridgeError> {
        // Update cache with new block data
        self.context.cache.update_with_block(block);

        // Process all kickoff machines
        for machine in &mut self.kickoff_machines {
            let events = machine.match_block(&self.cache);

            // TODO: we should order events by their presence in the block
            for event in events {
                machine.handle_with_context(&event, &mut self.context).await;
            }
        }

        // Process all round machines
        for machine in &mut self.round_machines {
            let events = machine.match_block(&self.cache);

            // TODO: we should order events by their presence in the block
            for event in events {
                machine.handle_with_context(&event, &mut self.context).await;
            }
        }

        Ok(())
    }
}
