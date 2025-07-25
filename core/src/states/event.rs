use std::sync::Arc;

use bitcoin::Witness;
use pgmq::PGMQueueExt;
use statig::awaitable::IntoStateMachineExt;

use crate::{
    database::{Database, DatabaseTransaction},
    deposit::{DepositData, KickoffData, OperatorData},
    errors::BridgeError,
};

use super::{
    block_cache, kickoff::KickoffStateMachine, round::RoundStateMachine, Owner, StateManager,
};

/// System events are events that are sent by other parts of clementine to the state machine
/// They are used to update the state machine
/// They are sent by the state manager to the state machine
#[derive(Debug, serde::Serialize, Clone, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SystemEvent {
    /// An event for a new finalized block
    /// So that state manager can update the states of all current state machines
    NewFinalizedBlock {
        block_id: u32,
        block: bitcoin::Block,
        height: u32,
    },
    /// An event for when a new operator is set in clementine
    /// So that the state machine can create a new round state machine to track the operator
    NewOperator { operator_data: OperatorData },
    /// An event for when a new kickoff is set in clementine
    /// So that the state machine can create a new kickoff state machine to track the kickoff status
    NewKickoff {
        kickoff_data: KickoffData,
        kickoff_height: u32,
        deposit_data: DepositData,
        payout_blockhash: Witness,
    },
}

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    /// Appends a  message to the state manager's message queue to create a new round state machine
    pub async fn dispatch_new_round_machine(
        db: Database,
        tx: DatabaseTransaction<'_, '_>,
        operator_data: OperatorData,
    ) -> Result<(), eyre::Report> {
        let queue_name = StateManager::<T>::queue_name();
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let message = SystemEvent::NewOperator { operator_data };
        queue
            .send_with_cxn(&queue_name, &message, &mut *(*tx))
            .await
            .map_err(|e| eyre::eyre!("Error sending NewOperator event: {:?}", e))?;
        Ok(())
    }

    /// Appends a  message to the state manager's message queue to create a new kickoff state machine
    pub async fn dispatch_new_kickoff_machine(
        db: Database,
        tx: DatabaseTransaction<'_, '_>,
        kickoff_data: KickoffData,
        kickoff_height: u32,
        deposit_data: DepositData,
        payout_blockhash: Witness,
    ) -> Result<(), eyre::Report> {
        let queue_name = StateManager::<T>::queue_name();
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let message = SystemEvent::NewKickoff {
            kickoff_data,
            kickoff_height,
            deposit_data,
            payout_blockhash,
        };
        queue
            .send_with_cxn(&queue_name, &message, &mut *(*tx))
            .await
            .map_err(|e| eyre::eyre!("Error sending NewKickoff event: {:?}", e))?;
        Ok(())
    }

    /// Updates the block cache with the new block
    /// Sets the block cache in the context
    pub fn update_block_cache(&mut self, block: &bitcoin::Block, block_height: u32) {
        let mut cache: block_cache::BlockCache = Default::default();
        cache.update_with_block(block, block_height);
        self.context.cache = Arc::new(cache);
    }

    /// Handles the system events
    pub async fn handle_event(
        &mut self,
        event: SystemEvent,
        dbtx: DatabaseTransaction<'_, '_>,
    ) -> Result<(), BridgeError> {
        match event {
            // Received when a block is finalized in Bitcoin
            SystemEvent::NewFinalizedBlock {
                block_id,
                block,
                height,
            } => {
                self.update_block_cache(&block, height);

                // Handle the finalized block on the owner (verifier or operator)
                self.owner
                    .handle_finalized_block(
                        dbtx,
                        block_id,
                        height,
                        self.context.cache.clone(),
                        None,
                    )
                    .await?;
                // Process the block on all state machines
                self.process_block_parallel(height).await?;
            }
            // Received when a new operator is set in clementine
            SystemEvent::NewOperator { operator_data } => {
                // Check if operator's state machine already exists.
                // This can happen if aggregator calls set_operator for the same operator multiple times.
                // In this case, we don't want to create a new state machine.
                for operator_machine in self.round_machines.iter() {
                    if operator_machine.operator_data.xonly_pk == operator_data.xonly_pk {
                        return Ok(());
                    }
                }

                let operator_machine = RoundStateMachine::new(operator_data)
                    .uninitialized_state_machine()
                    .init_with_context(&mut self.context)
                    .await;
                self.process_and_add_new_states_from_height(
                    vec![operator_machine],
                    vec![],
                    self.paramset.start_height,
                )
                .await?;
            }
            // Received when a new kickoff is detected
            SystemEvent::NewKickoff {
                kickoff_data,
                kickoff_height,
                deposit_data,
                payout_blockhash,
            } => {
                // Check if the kickoff machine already exists. If so do not add a new one.
                // This can happen if during block processing an error happens, reverting the state machines
                // but a new kickoff state was already dispatched during block processing.
                for kickoff_machine in self.kickoff_machines.iter() {
                    if kickoff_machine.kickoff_data == kickoff_data
                        && kickoff_machine.deposit_data == deposit_data
                        && kickoff_machine.payout_blockhash == payout_blockhash
                        && kickoff_machine.kickoff_height == kickoff_height
                    {
                        return Ok(());
                    }
                }

                let kickoff_machine = KickoffStateMachine::new(
                    kickoff_data,
                    kickoff_height,
                    deposit_data,
                    payout_blockhash,
                )
                .uninitialized_state_machine()
                .init_with_context(&mut self.context)
                .await;
                self.process_and_add_new_states_from_height(
                    vec![],
                    vec![kickoff_machine],
                    kickoff_height,
                )
                .await?;
            }
        }
        // Save the state machines to the database with the current block height
        // So that in case of a node restart the state machines can be restored
        self.save_state_to_db(self.next_height_to_process, Some(dbtx))
            .await?;
        Ok(())
    }
}
