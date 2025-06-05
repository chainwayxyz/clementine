pub use crate::builder::block_cache;
use crate::config::protocol::ProtocolParamset;
use crate::database::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use eyre::Context;
use futures::future::{join, join_all};
use kickoff::KickoffEvent;
use matcher::BlockMatcher;
use pgmq::PGMQueueExt;
use round::RoundEvent;
use statig::awaitable::{InitializedStateMachine, UninitializedStateMachine};
use statig::prelude::*;
use std::cmp::max;
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;

pub mod context;
mod event;
pub mod kickoff;
mod matcher;
pub mod round;
pub mod task;

pub use context::{Duty, Owner};
pub use event::SystemEvent;

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("State machine received event that it doesn't know how to handle: {0}")]
    UnhandledEvent(String),

    #[error(transparent)]
    Other(#[from] eyre::Report),
}
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
    pub db: Database,
    queue: PGMQueueExt,
    owner: T,
    round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
    kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
    context: context::StateContext<T>,
    paramset: &'static ProtocolParamset,
    next_height_to_process: u32,
}

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    pub fn queue_name() -> String {
        format!("{}_state_mgr_events", T::ENTITY_NAME)
    }

    pub async fn new(
        db: Database,
        owner: T,
        paramset: &'static ProtocolParamset,
    ) -> eyre::Result<Self> {
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;

        queue.create(&Self::queue_name()).await.wrap_err_with(|| {
            format!("Error creating pqmq queue with name {}", Self::queue_name())
        })?;

        let mut mgr = Self {
            context: context::StateContext::new(
                db.clone(),
                Arc::new(owner.clone()),
                Default::default(),
                paramset,
            ),
            db,
            owner,
            paramset,
            round_machines: Vec::new(),
            kickoff_machines: Vec::new(),
            queue,
            next_height_to_process: paramset.start_height,
        };

        mgr.load_from_db().await?;
        Ok(mgr)
    }

    /// Loads the state machines from the database.
    /// This method should be called when initializing the StateManager.
    ///
    /// # Errors
    /// Returns a `BridgeError` if the database operation fails
    pub async fn load_from_db(&mut self) -> Result<(), BridgeError> {
        // Start a transaction
        let mut tx = self.db.begin_transaction().await?;

        // Get the owner type from the context
        let owner_type = &self.context.owner_type;

        // First, check if we have any state saved
        let status = self
            .db
            .get_next_height_to_process(Some(&mut tx), owner_type)
            .await?;

        // If no state is saved, return early
        let Some(block_height) = status else {
            tracing::info!("No state machines found in the database");
            tx.commit().await?;
            return Ok(());
        };

        tracing::warn!("Loading state machines from block height {}", block_height);

        // Load kickoff machines
        let kickoff_machines = self
            .db
            .load_kickoff_machines(Some(&mut tx), owner_type)
            .await?;

        // Process and recreate kickoff machines
        for (state_json, kickoff_id, saved_block_height) in &kickoff_machines {
            tracing::debug!(
                "Loaded kickoff machine: state={}, block_height={}",
                state_json,
                saved_block_height
            );

            // Deserialize the machine state from JSON
            let machine: Result<UninitializedStateMachine<kickoff::KickoffStateMachine<T>>, _> =
                serde_json::from_str(state_json);

            match machine {
                Ok(uninitialized) => {
                    // Create a context for initialization
                    let mut ctx = context::StateContext::new(
                        self.db.clone(),
                        Arc::new(self.owner.clone()),
                        Default::default(),
                        self.paramset,
                    );

                    // Initialize the machine with the context
                    let initialized = uninitialized.init_with_context(&mut ctx).await;
                    self.kickoff_machines.push(initialized);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to deserialize kickoff machine with ID {}: {}",
                        kickoff_id,
                        e
                    );
                }
            }
        }

        // Load round machines
        let round_machines = self
            .db
            .load_round_machines(Some(&mut tx), owner_type)
            .await?;

        // Process and recreate round machines
        for (state_json, operator_xonly_pk, saved_block_height) in &round_machines {
            tracing::debug!(
                "Loaded round machine: state={}, block_height={}",
                state_json,
                saved_block_height
            );

            // Deserialize the machine state from JSON
            let machine: Result<UninitializedStateMachine<round::RoundStateMachine<T>>, _> =
                serde_json::from_str(state_json);

            match machine {
                Ok(uninitialized) => {
                    // Create a context for initialization
                    let mut ctx = context::StateContext::new(
                        self.db.clone(),
                        Arc::new(self.owner.clone()),
                        Default::default(),
                        self.paramset,
                    );

                    // Initialize the machine with the context
                    let initialized = uninitialized.init_with_context(&mut ctx).await;
                    self.round_machines.push(initialized);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to deserialize round machine with operator index {:?}: {}",
                        operator_xonly_pk,
                        e
                    );
                }
            }
        }

        tracing::info!(
            "Loaded {} kickoff machines and {} round machines from the database",
            kickoff_machines.len(),
            round_machines.len()
        );

        tx.commit().await?;
        self.next_height_to_process =
            u32::try_from(block_height).wrap_err(BridgeError::IntConversionError)?;
        Ok(())
    }
    #[cfg(test)]
    #[doc(hidden)]
    pub fn round_machines(&self) -> Vec<InitializedStateMachine<round::RoundStateMachine<T>>> {
        self.round_machines.clone()
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub fn kickoff_machines(
        &self,
    ) -> Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>> {
        self.kickoff_machines.clone()
    }

    /// Saves the state machines to the database. Resets the dirty flag for all machines after successful save.
    ///
    /// # Errors
    /// Returns a `BridgeError` if the database operation fails.
    ///
    /// # TODO
    /// We should only save `dirty` machines but we currently save all of them.
    pub async fn save_state_to_db(
        &mut self,
        block_height: u32,
        dbtx: Option<DatabaseTransaction<'_, '_>>,
    ) -> eyre::Result<()> {
        // Get the owner type from the context
        let owner_type = &self.context.owner_type;

        // Prepare kickoff machines data with direct serialization
        let kickoff_machines: eyre::Result<Vec<_>> = self
            .kickoff_machines
            .iter()
            .map(|machine| -> eyre::Result<_> {
                // Directly serialize the machine
                let state_json = serde_json::to_string(&machine).wrap_err_with(|| {
                    format!("Failed to serialize kickoff machine: {:?}", machine)
                })?;
                let kickoff_id =
                    serde_json::to_string(&machine.kickoff_data).wrap_err_with(|| {
                        format!("Failed to serialize kickoff id for machine: {:?}", machine)
                    })?;

                // Use the machine's dirty flag to determine if it needs updating
                Ok((state_json, (kickoff_id), machine.dirty))
            })
            .collect();

        // Prepare round machines data with direct serialization
        let round_machines: eyre::Result<Vec<_>> = self
            .round_machines
            .iter()
            .map(|machine| -> eyre::Result<_> {
                let state_json = serde_json::to_string(machine).wrap_err_with(|| {
                    format!("Failed to serialize round machine: {:?}", machine)
                })?;
                let operator_xonly_pk = machine.operator_data.xonly_pk;

                // Use the machine's dirty flag to determine if it needs updating
                Ok((state_json, (operator_xonly_pk), machine.dirty))
            })
            .collect();

        // Use the database function to save the state machines
        self.db
            .save_state_machines(
                dbtx,
                kickoff_machines?,
                round_machines?,
                block_height as i32,
                owner_type,
            )
            .await?;

        // Reset the dirty flag for all machines after successful save
        for machine in &mut self.kickoff_machines {
            if machine.dirty {
                machine
                    .handle_with_context(&KickoffEvent::SavedToDb, &mut self.context)
                    .await;
            }
        }

        for machine in &mut self.round_machines {
            if machine.dirty {
                machine
                    .handle_with_context(&RoundEvent::SavedToDb, &mut self.context)
                    .await;
            }
        }

        Ok(())
    }

    pub fn get_next_height_to_process(&self) -> u32 {
        self.next_height_to_process
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
    #[allow(clippy::type_complexity)]
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
        let mut unchanged_machines = Vec::new();
        let mut processing_futures = Vec::new();

        for machine in std::mem::take(machines).into_iter() {
            match machine.process_with_ctx(base_context) {
                ContextProcessResult::Processing(future) => processing_futures.push(future),
                ContextProcessResult::Unchanged(machine) => unchanged_machines.push(machine),
            }
        }

        (unchanged_machines, processing_futures)
    }

    pub async fn process_and_add_new_states_from_height(
        &mut self,
        new_round_machines: Vec<InitializedStateMachine<round::RoundStateMachine<T>>>,
        new_kickoff_machines: Vec<InitializedStateMachine<kickoff::KickoffStateMachine<T>>>,
        start_height: u32,
    ) -> Result<(), eyre::Report> {
        // save old round machines, only process new ones and then append old machines back
        let saved_round_machines = std::mem::take(&mut self.round_machines);
        let saved_kickoff_machines = std::mem::take(&mut self.kickoff_machines);

        self.round_machines = new_round_machines;
        self.kickoff_machines = new_kickoff_machines;

        for block_height in start_height..self.next_height_to_process {
            let block = self.db.get_full_block(None, block_height).await?;
            if let Some(block) = block {
                self.update_block_cache(&block, block_height);
                self.process_block_parallel(block_height).await?;
            } else {
                return Err(eyre::eyre!(
                    "Block at height {} not found in process_and_add_new_states_from_height",
                    block_height
                ));
            }
        }

        // append saved states
        self.round_machines.extend(saved_round_machines);
        self.kickoff_machines.extend(saved_kickoff_machines);

        Ok(())
    }

    /// It requires that the block cache is updated before calling this function.
    /// Moves all state machines forward in parallel.
    /// The state machines are updated until all of them stabilize in their state (ie.
    /// the block does not generate any new events)
    ///
    /// # Errors
    /// If the state machines do not stabilize after some iterations, we return an error.
    pub async fn process_block_parallel(&mut self, block_height: u32) -> Result<(), eyre::Report> {
        eyre::ensure!(
            self.context.cache.block_height == block_height,
            "Block cache is not updated"
        );

        let kickoff_machines_checkpoint = self.kickoff_machines.clone();
        let round_machines_checkpoint = self.round_machines.clone();

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
                tracing::warn!(
                    "Multiple errors occurred during state processing: owner: {:?}, errors: {:?}",
                    self.context.owner_type,
                    all_errors
                );
                // revert state machines to the saved state as the content of the machines might be changed before the error occurred
                self.kickoff_machines = kickoff_machines_checkpoint;
                self.round_machines = round_machines_checkpoint;
                // Return first error or create a combined error
                return Err(BridgeError::Error(format!(
                    "Multiple errors occurred during state processing: {:?}",
                    all_errors
                ))
                .into());
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
                #[cfg(debug_assertions)]
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

            // If the machines do not stabilize after a while, we return an error
            // TODO: https://github.com/chainwayxyz/clementine/issues/675
            // I think something like max(2 * num_kickoffs_per_round, number of utxos in a kickoff * 2) is a safe value
            if iterations > 100000 {
                return Err(eyre::eyre!(
                    r#"{}/{} kickoff and {}/{} round state machines did not stabilize after 100000 iterations, debug repr of changed machines:
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
                ));
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

        drop(kickoff_futures);
        drop(round_futures);

        // Set back the original machines
        self.round_machines = final_round_machines;
        self.kickoff_machines = final_kickoff_machines;
        self.next_height_to_process = max(block_height + 1, self.next_height_to_process);

        Ok(())
    }
}
