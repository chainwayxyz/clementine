use std::sync::Arc;

use bitcoin::Witness;
use eyre::{Context, OptionExt};
use pgmq::PGMQueueExt;
use statig::awaitable::{InitializedStateMachine, IntoStateMachineExt};
use tokio::sync::Mutex;

use crate::{
    database::{Database, DatabaseTransaction},
    deposit::{DepositData, KickoffData, OperatorData},
    errors::BridgeError,
    states::{
        context::{DutyResult, StateContext},
        round::RoundEvent,
    },
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
    /// The LCP for this Bitcoin block height was persisted.
    LcpProcessed { height: u32 },
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

    pub async fn dispatch_lcp_processed(
        db: &Database,
        tx: DatabaseTransaction<'_, '_>,
        height: u32,
    ) -> Result<(), eyre::Report> {
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        queue
            .send_with_cxn(
                &Self::queue_name(),
                &SystemEvent::LcpProcessed { height },
                &mut **tx,
            )
            .await
            .wrap_err("Error sending LcpProcessed event")?;
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
                block_id: _,
                block,
                height,
            } => {
                if self.next_height_to_process != height {
                    return Err(eyre::eyre!("Finalized block arrived to state manager out of order. Expected: block at height {}, Got: block at height {}", self.next_height_to_process, height).into());
                }

                let mut context = self.new_context(dbtx.clone(), &block, height)?;

                self.process_block_parallel(&mut context).await?;

                self.last_finalized_block = Some(context.cache.clone());
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

                // Initialize context using the block just before the start height
                // so subsequent processing can begin from start_height
                let prev_height = self.config.protocol_paramset.start_height.saturating_sub(1);
                let init_block = {
                    let mut guard = dbtx.lock().await;
                    self.get_block(Some(&mut *guard), prev_height).await?
                };

                let mut context = self.new_context(dbtx.clone(), &init_block, prev_height)?;

                let operator_machine = RoundStateMachine::new(operator_data)
                    .uninitialized_state_machine()
                    .init_with_context(&mut context)
                    .await;

                if !context.errors.is_empty() {
                    return Err(eyre::eyre!(
                        "Multiple errors occurred during RoundStateMachine initialization: {:?}",
                        context.errors
                    )
                    .into());
                }

                self.process_and_add_new_states_from_height(
                    dbtx.clone(),
                    vec![operator_machine],
                    vec![],
                    self.config.protocol_paramset.start_height,
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
                if !self.owner.is_kickoff_relevant_for_owner(&kickoff_data) {
                    return Ok(());
                }

                // Initialize context using the block just before the kickoff height
                // so subsequent processing can begin from kickoff_height
                let prev_height = kickoff_height.saturating_sub(1);
                let init_block = {
                    let mut guard = dbtx.lock().await;
                    self.get_block(Some(&mut *guard), prev_height).await?
                };

                let mut context = self.new_context(dbtx.clone(), &init_block, prev_height)?;

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
                    deposit_data.clone(),
                    payout_blockhash.clone(),
                )
                .uninitialized_state_machine()
                .init_with_context(&mut context)
                .await;

                if !context.errors.is_empty() {
                    return Err(eyre::eyre!(
                        "Multiple errors occurred during KickoffStateMachine initialization: {:?}",
                        context.errors
                    )
                    .into());
                }

                self.process_and_add_new_states_from_height(
                    dbtx.clone(),
                    vec![],
                    vec![kickoff_machine],
                    kickoff_height,
                )
                .await?;

                if self
                    .last_processed_lcp
                    .is_some_and(|height| height >= kickoff_height)
                {
                    self.check_if_kickoff_malicious(
                        &payout_blockhash,
                        &kickoff_data,
                        &deposit_data,
                        &mut context,
                    )
                    .await?;
                }
            }
            SystemEvent::LcpProcessed { height } => {
                let prev = self.last_processed_lcp;
                let kickoffs: Vec<_> = self
                    .kickoff_machines
                    .iter()
                    .filter(|machine| {
                        prev.is_none_or(|prev| prev < machine.kickoff_height)
                            && machine.kickoff_height <= height
                    })
                    .map(|machine| {
                        (
                            machine.payout_blockhash.clone(),
                            machine.kickoff_data,
                            machine.deposit_data.clone(),
                        )
                    })
                    .collect();

                let mut context = self.new_context_with_block_cache(
                    dbtx.clone(),
                    self.last_finalized_block.clone().ok_or_eyre(
                        "Last finalized block not found, should always be Some after initialization",
                    )?,
                )?;
                for (witness, kickoff_data, deposit_data) in kickoffs {
                    self.check_if_kickoff_malicious(
                        &witness,
                        &kickoff_data,
                        &deposit_data,
                        &mut context,
                    )
                    .await?;
                }
                self.last_processed_lcp = Some(height);
            }
        };

        let mut context = self.new_context_with_block_cache(
            dbtx,
            self.last_finalized_block.clone().ok_or_eyre(
                "Last finalized block not found, should always be Some after initialization",
            )?,
        )?;

        // Save the state machines to the database with the current block height
        // So that in case of a node restart the state machines can be restored
        self.save_state_to_db(&mut context).await?;

        Ok(())
    }

    fn get_round_machine(
        &mut self,
        operator_xonly_pk: &bitcoin::XOnlyPublicKey,
    ) -> Option<&mut InitializedStateMachine<RoundStateMachine<T>>> {
        self.round_machines
            .iter_mut()
            .find(|machine| &machine.operator_data.xonly_pk == operator_xonly_pk)
    }

    async fn check_if_kickoff_malicious(
        &mut self,
        payout_blockhash: &Witness,
        kickoff_data: &KickoffData,
        deposit_data: &DepositData,
        context: &mut StateContext<T>,
    ) -> Result<(), BridgeError> {
        let challenged_before = self
            .get_round_machine(&kickoff_data.operator_xonly_pk)
            .ok_or_else(|| {
                eyre::eyre!(
                    "Round machine not found for operator {} while checking kickoff",
                    kickoff_data.operator_xonly_pk
                )
            })?
            .challenged_rounds
            .contains(&kickoff_data.round_idx);

        let result = context
            .dispatch_duty(super::Duty::CheckIfKickoffMalicious {
                kickoff_witness: payout_blockhash.clone(),
                deposit_data: deposit_data.clone(),
                kickoff_data: *kickoff_data,
                challenged_before,
            })
            .await
            .wrap_err("Error while checking if kickoff is malicious")?;

        match result {
            DutyResult::CheckIfKickoffMalicious { challenged } => {
                if challenged && !challenged_before {
                    self.get_round_machine(&kickoff_data.operator_xonly_pk)
                        .ok_or_eyre("Round machine disappeared while checking kickoff")?
                        .handle_with_context(
                            &RoundEvent::SetChallenged {
                                round_idx: kickoff_data.round_idx,
                            },
                            context,
                        )
                        .await;
                }
            }
            other => {
                return Err(eyre::eyre!(
                    "Expected CheckIfKickoffMalicious duty result, got {other:?}"
                )
                .into());
            }
        }

        Ok(())
    }
}
