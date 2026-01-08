use std::sync::Arc;

use bitcoin::{consensus::Encodable, Witness};
use eyre::OptionExt;
use pgmq::PGMQueueExt;
use statig::awaitable::IntoStateMachineExt;
use tokio::sync::Mutex;

use crate::{
    database::{Database, DatabaseTransaction},
    deposit::{DepositData, KickoffData, OperatorData},
    states::Duty,
};
use clementine_errors::BridgeError;

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
        db: &Database,
        tx: DatabaseTransaction<'_>,
        operator_data: OperatorData,
    ) -> Result<(), eyre::Report> {
        let queue_name = Self::queue_name();
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
        db: &Database,
        tx: DatabaseTransaction<'_>,
        kickoff_data: KickoffData,
        kickoff_height: u32,
        deposit_data: DepositData,
        payout_blockhash: Witness,
    ) -> Result<(), eyre::Report> {
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let queue_name = Self::queue_name();

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
                    return Err(eyre::eyre!("Finalized block arrived to state manager out of order. Expected: block at height {}, Got: block at height {}", self.next_height_to_process, height).into());
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
                // if kickoff is not relevant for the owner, do not process it
                // only case right now is if owner is operator and kickoff is not of their own
                if !self.owner.is_kickoff_relevant_for_owner(&kickoff_data) {
                    return Ok(());
                }

                // check for duplicates
                for kickoff_machine in self.kickoff_machines.iter() {
                    // if they do not have the same kickoff data (same operator + kickoff utxo), it's definitely not a duplicate
                    if kickoff_machine.kickoff_data != kickoff_data {
                        continue;
                    }
                    let matches = [
                        kickoff_machine.deposit_data == deposit_data,
                        kickoff_machine.payout_blockhash == payout_blockhash,
                        kickoff_machine.kickoff_height == kickoff_height,
                    ];
                    let match_count = matches.iter().filter(|&&b| b).count();

                    // sanity check, should never be a partial match, otherwise something is really wrong with the bitcoin sync
                    // this error is basically just to make sure we only added finalized kickoffs to the state manager. If it was not finalized + reorged, there can be a mismatch here.
                    match match_count {
                        3 => return Ok(()), // exact duplicate, skip
                        0 => {}             // no match, continue checking other machines
                        n => {
                            let mut raw_payout_blockhash = Vec::new();
                            payout_blockhash
                                .consensus_encode(&mut raw_payout_blockhash)
                                .map_err(|e| {
                                    eyre::eyre!("Error encoding payout blockhash: {}", e)
                                })?;
                            let payout_blockhash_hex = hex::encode(raw_payout_blockhash);
                            let mut raw_existing_payout_blockhash = Vec::new();
                            kickoff_machine
                                .payout_blockhash
                                .consensus_encode(&mut raw_existing_payout_blockhash)
                                .map_err(|e| {
                                    eyre::eyre!("Error encoding existing payout blockhash: {}", e)
                                })?;
                            let existing_payout_blockhash_hex =
                                hex::encode(raw_existing_payout_blockhash);
                            return Err(eyre::eyre!(
                            "Partial kickoff({:?}) match detected ({n} of 3 fields match). This indicates data corruption or inconsistency. New deposit data: {:?}, Existing deposit data: {:?}, New kickoff height: {}, Existing kickoff height: {}, New payout blockhash: {}, Existing payout blockhash: {}",
                            kickoff_data,
                            deposit_data,
                            kickoff_machine.deposit_data,
                            kickoff_height,
                            kickoff_machine.kickoff_height,
                            payout_blockhash_hex,
                            existing_payout_blockhash_hex,
                            ).into());
                        }
                    }
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
                    payout_blockhash,
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
                // if everything is fine, add the relevant txs to the tx sender
                // this will already be added normally, but if there was a db loss and we are resyncing, the txs will not be added.
                // so we add them with this duty.
                context
                    .dispatch_duty(Duty::AddRelevantTxsToTxSender {
                        kickoff_data,
                        deposit_data,
                    })
                    .await?;
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
}
