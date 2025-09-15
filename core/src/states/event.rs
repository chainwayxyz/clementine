use std::sync::Arc;

use bitcoin::Witness;
use eyre::OptionExt;
use pgmq::PGMQueueExt;
use statig::awaitable::IntoStateMachineExt;
use tokio::sync::Mutex;

use crate::{
    database::{Database, DatabaseTransaction},
    deposit::{DepositData, KickoffData, OperatorData},
    errors::BridgeError,
};

use super::{kickoff::KickoffStateMachine, round::RoundStateMachine, Owner, StateManager};

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

    /// Handles the system events
    pub async fn handle_event(
        &mut self,
        event: SystemEvent,
        dbtx: Arc<Mutex<sqlx::Transaction<'static, sqlx::Postgres>>>,
    ) -> Result<(), BridgeError> {
        match event {
            // Received when a block is finalized in Bitcoin
            SystemEvent::NewFinalizedBlock {
                block_id,
                block,
                height,
            } => {
                if self.next_height_to_process != height {
                    tracing::warn!("Finalized block arrived to state manager out of order. Ignoring block. This can happen for some blocks during restarts. Otherwise it might be due to an error. Expected: {}, Got: {}", self.next_height_to_process, height);
                    return Ok(());
                }

                let mut context = self.new_context(dbtx.clone(), &block, height)?;

                // Handle the finalized block on the owner (verifier or operator)
                {
                    let mut guard = dbtx.lock().await;
                    self.owner
                        .handle_finalized_block(
                            &mut guard,
                            block_id,
                            height,
                            context.cache.clone(),
                            None,
                        )
                        .await?;
                }

                self.process_block_parallel(&mut context).await?;

                self.last_finalized_block = Some(block);
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

                let mut context = self.new_context(
                    dbtx.clone(),
                    &self
                        .last_finalized_block
                        .as_ref()
                        .ok_or_eyre("Last finalized block is not set")?
                        .clone(),
                    self.next_height_to_process - 1,
                )?;

                let operator_machine = RoundStateMachine::new(operator_data)
                    .uninitialized_state_machine()
                    .init_with_context(&mut context)
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
                let mut context = self.new_context(
                    dbtx.clone(),
                    &self
                        .last_finalized_block
                        .as_ref()
                        .ok_or_eyre("Last finalized block is not set")?
                        .clone(),
                    self.next_height_to_process - 1,
                )?;

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
                .init_with_context(&mut context)
                .await;

                self.process_and_add_new_states_from_height(
                    vec![],
                    vec![kickoff_machine],
                    kickoff_height,
                )
                .await?;
            }
        }

        let mut context = self.new_context(
            dbtx,
            &self
                .last_finalized_block
                .as_ref()
                .ok_or_eyre("Last finalized block is not set")?
                .clone(),
            self.next_height_to_process - 1,
        )?;

        // Save the state machines to the database with the current block height
        // So that in case of a node restart the state machines can be restored
        self.save_state_to_db(&mut context).await?;

        Ok(())
    }
}
