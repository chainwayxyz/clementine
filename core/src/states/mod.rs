use crate::builder::transaction::{DepositData, OperatorData};
use crate::config::protocol::ProtocolParamset;
use crate::database::Database;
use crate::errors::BridgeError;
use bitcoin::Block;
use futures::future::{self, join, join_all, Map};
use matcher::BlockMatcher;
use statig::awaitable::InitializedStateMachine;
use statig::prelude::*;
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;
use tonic::async_trait;

mod block_cache;
mod context;
mod kickoff;
mod matcher;
mod round;
pub mod syncer;

pub use context::Duty;
pub use context::Owner;

pub(crate) enum ContextProcessResult<
    T: Owner,
    M: IntoStateMachine,
    Fut: Future<Output = (InitializedStateMachine<M>, context::StateContext<T>)> + Send,
> {
    Unchanged(InitializedStateMachine<M>),
    Processing(Fut),
}

/// Utility trait to make processing generic
pub(crate) trait ContextProcessor<T: Owner, M: IntoStateMachine> {
    /// Processes the machine with the given state context (which contains the block cache)
    /// If the machine is unchanged, it is returned as is. Otherwise, the machine is processed
    /// and the result is returned as a future that processes the new events.
    fn process_with_ctx(
        self,
        block: &context::StateContext<T>,
    ) -> ContextProcessResult<
        T,
        M,
        impl Future<Output = (InitializedStateMachine<M>, context::StateContext<T>)> + Send,
    >;
}

/// Generic implementation for all state machines
impl<T, M> ContextProcessor<T, M> for InitializedStateMachine<M>
where
    T: Owner,
    for<'evt, 'ctx> M: IntoStateMachine<Event<'evt> = M::StateEvent, Context<'ctx> = context::StateContext<T>>
        + Send
        + BlockMatcher
        + Clone,
    M::State: awaitable::State<M> + 'static + Send,
    for<'sub> M::Superstate<'sub>: awaitable::Superstate<M> + Send,
    for<'evt> M::Event<'evt>: Send + Sync,
{
    fn process_with_ctx(
        mut self,
        block: &context::StateContext<T>,
    ) -> ContextProcessResult<T, M, impl Future<Output = (Self, context::StateContext<T>)> + Send>
    {
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

// New state manager to hold and coordinate state machines
#[derive(Debug)]
pub struct StateManager<T: Owner> {
    db: Database,
    owner: T,
    round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    context: context::StateContext<T>,
    paramset: &'static ProtocolParamset,
    consumer_handle: String,
    last_processed_block_height: u32,
    start_block_height: u32,
}

impl<T: Owner + 'static> StateManager<T> {
    pub fn new(
        db: Database,
        handler: T,
        paramset: &'static ProtocolParamset,
        consumer_handle: String,
        start_block_height: u32,
    ) -> Self {
        Self {
            context: context::StateContext::new(
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
            consumer_handle,
            last_processed_block_height: 0,
            start_block_height,
        }
    }

    pub fn load_from_db(&mut self) -> Result<(), BridgeError> {
        // TODO: implement
        Ok(())
    }

    pub fn save_to_db(&self) -> Result<(), BridgeError> {
        // TODO: implement
        Ok(())
    }

    fn create_context(
        handler: T,
        db: Database,
        cache: block_cache::BlockCache,
        paramset: &'static ProtocolParamset,
    ) -> context::StateContext<T> {
        context::StateContext {
            db: db.clone(),
            owner: Arc::new(handler),
            cache: Arc::new(cache),
            new_kickoff_machines: Vec::new(),
            new_round_machines: Vec::new(),
            errors: Vec::new(),
            paramset,
        }
    }

    /// Updates the machines using the context and returns machines without
    /// events and futures that process new events for machines that changed.
    /// Empties the `machines` vector.
    ///
    /// # Parameters
    /// * `machines`: A mutable reference to the vector of state machines to update.
    /// * `base_context`: A reference to the base state context.
    ///
    /// # Returns
    /// A tuple of the unchanged machines and the futures that process new
    /// events for machines that generated events.
    ///
    /// # Type Parameters
    /// * `M`: The type of the state machine.
    /// * `a`: The lifetime of the state context reference (the future captures the context by reference).
    fn update_machines<'a, M>(
        machines: &mut Vec<InitializedStateMachine<M>>,
        base_context: &'a context::StateContext<T>,
    ) -> (
        Vec<InitializedStateMachine<M>>,
        Vec<
            impl Future<Output = (InitializedStateMachine<M>, context::StateContext<T>)> + Send + 'a,
        >,
    )
    where
        M: IntoStateMachine + Send + Sync + 'static,
        M::State: Send + Sync + 'static,
        InitializedStateMachine<M>: ContextProcessor<T, M>,
    {
        let mut new_machines = Vec::new();
        let mut processing_futures = Vec::new();

        for machine in std::mem::take(machines).into_iter() {
            match machine.process_with_ctx(base_context) {
                ContextProcessResult::Processing(future) => processing_futures.push(future),
                ContextProcessResult::Unchanged(machine) => new_machines.push(machine),
            }
        }

        (new_machines, processing_futures)
    }

    pub async fn process_states_from_height(
        &mut self,
        new_round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
        new_kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
        start_height: u32,
    ) -> Result<(), BridgeError> {
        // save old round machines, only process new ones and then append old machines back
        let saved_round_machines = std::mem::take(&mut self.round_machines);
        let saved_kickoff_machines = std::mem::take(&mut self.kickoff_machines);

        self.round_machines = new_round_machines;
        self.kickoff_machines = new_kickoff_machines;

        for block_height in start_height..self.last_processed_block_height + 1 {
            let block = self.db.get_full_block(None, block_height).await?;
            if let Some(block) = block {
                self.process_block_parallel(&block, block_height).await?;
            } else {
                return Err(BridgeError::Error(format!(
                    "Block at height {} not found",
                    block_height
                )));
            }
        }

        // append saved states
        self.round_machines.extend(saved_round_machines);
        self.kickoff_machines.extend(saved_kickoff_machines);

        Ok(())
    }

    /// Processes the block and moves all state machines forward in parallel.
    /// The state machines are updated until all of them stabilize in their state (ie.
    /// the block does not generate any new events)
    ///
    /// # Errors
    /// If the state machines do not stabilize after 50 iterations, we return an error.
    pub async fn process_block_parallel(
        &mut self,
        block: &Block,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let mut cache: block_cache::BlockCache = Default::default();
        cache.update_with_block(block, block_height);
        self.context.cache = Arc::new(cache);

        // Process all machines, for those unaffected collect them them, otherwise return
        // a future that processes the new events.
        let (mut final_kickoff_machines, mut kickoff_futures) =
            Self::update_machines(&mut self.kickoff_machines, &self.context);
        let (mut final_round_machines, mut round_futures) =
            Self::update_machines(&mut self.round_machines, &self.context);

        let mut iterations = 0;

        // On each iteration, we'll update the changed machines until all machines
        // stabilize in their state.
        while !kickoff_futures.is_empty() || !round_futures.is_empty() {
            // Execute all futures in parallel
            let (kickoff_results, round_results) =
                join(join_all(kickoff_futures), join_all(round_futures)).await;

            // Unzip the results into updated machines and state contexts
            let (mut changed_kickoff_machines, mut kickoff_contexts): (Vec<_>, Vec<_>) =
                kickoff_results.into_iter().unzip();
            let (mut changed_round_machines, mut round_contexts): (Vec<_>, Vec<_>) =
                round_results.into_iter().unzip();

            // Merge and handle errors
            let mut all_errors = Vec::new();
            for ctx in kickoff_contexts.iter_mut().chain(round_contexts.iter_mut()) {
                all_errors.extend(std::mem::take(&mut ctx.errors));
            }

            if !all_errors.is_empty() {
                // Return first error or create a combined error
                return Err(BridgeError::Error(
                    "Multiple errors occurred during state processing".into(),
                ));
            }

            // Append the newly generated state machines into the changed machines list
            for ctx in kickoff_contexts.iter_mut().chain(round_contexts.iter_mut()) {
                #[cfg(debug_assertions)]
                for machine in &ctx.new_round_machines {
                    if !machine.dirty {
                        panic!(
                            "Round machine not dirty despite having been newly created: {:?}",
                            machine.state()
                        );
                    }
                }
                for machine in &ctx.new_kickoff_machines {
                    if !machine.dirty {
                        panic!(
                            "Kickoff machine not dirty despite having been newly created: {:?}",
                            machine.state()
                        );
                    }
                }
                changed_round_machines.extend(std::mem::take(&mut ctx.new_round_machines));
                changed_kickoff_machines.extend(std::mem::take(&mut ctx.new_kickoff_machines));
            }

            if iterations > 500 {
                return Err(BridgeError::Error(format!(
                    r#"{}/{} kickoff and {}/{} round state machines did not stabilize after 500 iterations, debug repr of changed machines:
                        ---- Kickoff machines ----
                        {:?}
                        ---- Round machines ----
                        {:?}
                        "#,
                    changed_kickoff_machines.len(),
                    final_kickoff_machines.len() + changed_kickoff_machines.len(),
                    changed_round_machines.len(),
                    final_round_machines.len() + changed_round_machines.len(),
                    changed_kickoff_machines
                        .iter()
                        .map(|m| m.state())
                        .collect::<Vec<_>>(),
                    changed_round_machines
                        .iter()
                        .map(|m| m.state())
                        .collect::<Vec<_>>(),
                )));
            }

            // Reprocess changed machines and commit these futures to be handled
            // in the next round If they're empty, we'll exit the loop.
            let (finalized_kickoff_machines, new_kickoff_futures) =
                Self::update_machines(&mut changed_kickoff_machines, &self.context);
            let (finalized_round_machines, new_round_futures) =
                Self::update_machines(&mut changed_round_machines, &self.context);
            final_kickoff_machines.extend(finalized_kickoff_machines);
            final_round_machines.extend(finalized_round_machines);

            // Update the futures to be processed
            kickoff_futures = new_kickoff_futures;
            round_futures = new_round_futures;
            iterations += 1;
        }

        // TODO: commit to db

        // Set back the original machines
        self.round_machines = final_round_machines;
        self.kickoff_machines = final_kickoff_machines;

        Ok(())
    }
}
