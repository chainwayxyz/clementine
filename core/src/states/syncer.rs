use statig::awaitable::{InitializedStateMachine, IntoStateMachineExt};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::{
    bitcoin_syncer::BitcoinSyncerEvent, builder::transaction::OperatorData, database::Database,
    errors::BridgeError,
};

use super::{context::Owner, round::RoundStateMachine, StateManager};

pub async fn run<T>(
    state_manager: Arc<Mutex<StateManager<T>>>,
    db: Database,
    poll_delay: Duration,
) -> Result<JoinHandle<Result<(), BridgeError>>, BridgeError>
where
    T: Owner + 'static,
{
    let handle = tokio::spawn(async move {
        let consumer_handle = {
            let state_manager = state_manager.lock().await;
            state_manager.consumer_handle.clone()
        };
        tracing::info!(
            "Starting state manager syncing with handle {}",
            consumer_handle
        );
        loop {
            let result: Result<bool, BridgeError> = async {
                let mut dbtx = db.begin_transaction().await?;
                let is_chain_tip_update = async {
                    let event = db.get_event_and_update(&mut dbtx, &consumer_handle).await?;
                    Ok::<bool, BridgeError>(match event {
                        Some(event) => match event {
                            BitcoinSyncerEvent::NewBlock(block_id) => {
                                let mut states = state_manager.lock().await;
                                let current_tip_height = db
                                    .get_block_info_from_id(Some(&mut dbtx), block_id)
                                    .await?
                                    .ok_or(BridgeError::Error("Block not found".to_string()))?
                                    .1;
                                let mut new_tip = false;
                                // update states to catch up to finalized chain
                                while states.last_processed_block_height
                                    < current_tip_height - states.paramset.finalized_depth + 1
                                {
                                    let next_height = states.last_processed_block_height + 1;
                                    let block =
                                        db.get_full_block(Some(&mut dbtx), next_height).await?;
                                    if let Some(block) = block {
                                        new_tip = true;
                                        states.process_block_parallel(&block, next_height).await?;
                                    } else {
                                        return Err(BridgeError::Error(format!(
                                            "Block at height {} not found",
                                            states.last_processed_block_height + 1
                                        )));
                                    }
                                }
                                new_tip
                            }
                            BitcoinSyncerEvent::ReorgedBlock(_) => false,
                        },
                        None => false,
                    })
                }
                .await?;
                dbtx.commit().await?;
                if is_chain_tip_update {
                    // Don't wait in new events
                    return Ok(true);
                }

                Ok(false)
            }
            .await;

            match result {
                Ok(true) => {}
                Ok(false) => {
                    tokio::time::sleep(poll_delay).await;
                }
                Err(e) => {
                    tracing::error!("State manager syncing error: {:?}", e);
                    tokio::time::sleep(poll_delay).await;
                }
            }
        }
    });

    Ok(handle)
}

pub async fn add_new_round_machine<T>(
    state_manager: Arc<Mutex<StateManager<T>>>,
    operator_data: OperatorData,
    operator_idx: u32,
) -> Result<(), BridgeError>
where
    T: Owner + 'static,
{
    let mut state_manager = state_manager.lock().await;
    let round_state_machine = super::round::RoundStateMachine::new(operator_data, operator_idx)
        .uninitialized_state_machine();
    let initialized_state = round_state_machine
        .init_with_context(&mut state_manager.context)
        .await;
    let start_height = state_manager.start_block_height;
    // process from start
    state_manager
        .process_states_from_height(vec![initialized_state], vec![], start_height)
        .await?;
    Ok(())
}
