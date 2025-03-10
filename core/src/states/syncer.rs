use crate::{
    bitcoin_syncer::BitcoinSyncerEvent, builder::transaction::OperatorData, database::Database,
};
use pgmq::{Message, PGMQueueExt};
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{
    builder::transaction::DepositData, config::protocol::ProtocolParamset,
    database::DatabaseTransaction, errors::BridgeError, rpc::clementine::KickoffId,
    states::SystemEvent,
};

use super::{context::Owner, StateManager};

/// Starts a new thread to periodically fetch new blocks from bitcoin_syncer
pub async fn fetch_new_blocks(
    last_processed_block_height: u32,
    consumer_handle: String,
    db: Database,
    poll_delay: Duration,
    paramset: &'static ProtocolParamset,
) -> JoinHandle<Result<(), eyre::Report>> {
    tokio::spawn(async move {
        tracing::info!(
            "Starting state manager block syncing with consumer handle {} starting from height {}",
            consumer_handle,
            last_processed_block_height
        );
        // variable to store locally last sent height
        let mut last_sent_height = last_processed_block_height;
        let mut num_consecutive_errors = 0;
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        loop {
            let result: Result<bool, eyre::Report> = async {
                let mut dbtx = db.begin_transaction().await?;
                let has_updated_states = async {
                    let event = db.get_event_and_update(&mut dbtx, &consumer_handle).await?;
                    Ok::<bool, eyre::Report>(match event {
                        Some(event) => match event {
                            BitcoinSyncerEvent::NewBlock(block_id) => {
                                let current_tip_height = db
                                    .get_block_info_from_id(Some(&mut dbtx), block_id)
                                    .await?
                                    .ok_or(eyre::eyre!("Block not found"))?
                                    .1;
                                let mut new_tip = false;
                                // update states to catch up to finalized chain
                                while last_sent_height
                                    < current_tip_height - paramset.finality_depth + 1
                                {
                                    let next_height = last_sent_height + 1;
                                    let block =
                                        db.get_full_block(Some(&mut dbtx), next_height).await?;
                                    if let Some(block) = block {
                                        new_tip = true;
                                        let event = SystemEvent::NewBlock {
                                            block,
                                            height: next_height,
                                        };
                                        queue
                                            .send_with_cxn(&consumer_handle, &event, &mut *dbtx)
                                            .await
                                            .map_err(|e| {
                                                BridgeError::Error(format!(
                                                    "Error sending event: {:?}",
                                                    e
                                                ))
                                            })?;
                                    } else {
                                        return Err(eyre::eyre!(format!(
                                            "Block at height {} not found",
                                            next_height
                                        )));
                                    }
                                    last_sent_height += 1;
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
                if has_updated_states {
                    // Don't wait in new events
                    return Ok(true);
                }

                Ok(false)
            }
            .await;

            match result {
                Ok(true) => {
                    num_consecutive_errors = 0;
                }
                Ok(false) => {
                    num_consecutive_errors = 0;
                    tokio::time::sleep(poll_delay).await;
                }
                Err(e) => {
                    tracing::error!("State manager block fetch error: {:?}", e);
                    num_consecutive_errors += 1;
                    if num_consecutive_errors > 50 {
                        return Err(eyre::eyre!(
                            "Too many consecutive state machine block fetching errors"
                        ));
                    }
                    tokio::time::sleep(poll_delay).await;
                }
            }
        }
    })
}

pub async fn add_new_round_machine(
    db: Database,
    consumer_handle: String,
    tx: DatabaseTransaction<'_, '_>,
    operator_data: OperatorData,
    operator_idx: u32,
) -> Result<(), eyre::Report> {
    let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
    let message = SystemEvent::NewOperator {
        operator_data,
        operator_idx,
    };
    queue
        .send_with_cxn(&consumer_handle, &message, &mut *(*tx))
        .await
        .map_err(|e| BridgeError::Error(format!("Error sending NewOperator event: {:?}", e)))?;
    Ok(())
}

pub async fn add_new_kickoff_machine(
    db: Database,
    consumer_handle: String,
    tx: DatabaseTransaction<'_, '_>,
    kickoff_id: KickoffId,
    kickoff_height: u32,
    deposit_data: DepositData,
) -> Result<(), eyre::Report> {
    let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
    let message = SystemEvent::NewKickoff {
        kickoff_id,
        kickoff_height,
        deposit_data,
    };
    queue
        .send_with_cxn(&consumer_handle, &message, &mut *(*tx))
        .await
        .map_err(|e| BridgeError::Error(format!("Error sending NewOperator event: {:?}", e)))?;
    Ok(())
}

pub async fn run_state_manager<T>(
    mut state_manager: StateManager<T>,
    poll_delay: Duration,
) -> (JoinHandle<Result<(), eyre::Report>>, oneshot::Sender<()>)
where
    T: Owner + std::fmt::Debug + 'static,
{
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        tracing::info!(
            "Starting state manager main run thread with consumer handle {}",
            state_manager.consumer_handle
        );
        let db = state_manager.db.clone();
        let mut num_consecutive_errors = 0;

        loop {
            // Check if shutdown signal was received or the channel was closed (meaning the operator was dropped)
            if shutdown_rx.try_recv() != Err(oneshot::error::TryRecvError::Empty) {
                tracing::info!("Shutdown signal received, stopping state manager");
                break Ok(());
            }

            let poll_result: Result<bool, BridgeError> = async {
                let new_event_received = async {
                    let mut dbtx = db.begin_transaction().await?;
                    let new_event: Option<Message<SystemEvent>> = state_manager
                        .queue
                        .read_with_cxn(&state_manager.consumer_handle, 1, &mut *dbtx)
                        .await
                        .map_err(|e| BridgeError::Error(format!("Error reading event: {:?}", e)))?;
                    let return_value = Ok::<bool, BridgeError>(match new_event {
                        Some(event) => {
                            let event_id = event.msg_id;
                            state_manager.handle_event(event.message, &mut dbtx).await?;
                            // handled event, delete it from queue
                            state_manager
                                .queue
                                .archive_with_cxn(
                                    &state_manager.consumer_handle,
                                    event_id,
                                    &mut *dbtx,
                                )
                                .await
                                .map_err(|e| {
                                    BridgeError::Error(format!("Error deleting event: {:?}", e))
                                })?;
                            true
                        }
                        None => false,
                    });
                    dbtx.commit().await.map_err(|e| {
                        BridgeError::Error(format!("Error committing transaction: {:?}", e))
                    })?;
                    return_value
                }
                .await?;

                if new_event_received {
                    // Don't wait in case new event was received
                    return Ok(true);
                }
                Ok(false)
            }
            .await;

            match poll_result {
                Ok(true) => {
                    num_consecutive_errors = 0;
                }
                Ok(false) => {
                    num_consecutive_errors = 0;
                    tokio::time::sleep(poll_delay).await;
                }
                Err(e) => {
                    tracing::error!("State manager run loop error: {:?}", e);
                    num_consecutive_errors += 1;
                    if num_consecutive_errors > 50 {
                        return Err(eyre::eyre!("Too many consecutive state machine errors"));
                    }
                    tokio::time::sleep(poll_delay).await;
                }
            }
        }
    });

    (handle, shutdown_tx)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::time::timeout;
    use tonic::async_trait;

    use crate::{
        builder::transaction::{ContractContext, TransactionType, TxHandler},
        config::{protocol::ProtocolParamsetName, BridgeConfig},
        states::Duty,
        test::common::create_test_config_with_thread_name,
    };

    use super::*;

    #[derive(Clone, Debug)]
    struct MockHandler;

    #[async_trait]
    impl Owner for MockHandler {
        const OWNER_TYPE: &'static str = "MockHandler";

        async fn handle_duty(&self, _: Duty) -> Result<(), BridgeError> {
            Ok(())
        }

        async fn create_txhandlers(
            &self,
            _: TransactionType,
            _: ContractContext,
        ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
            Ok(BTreeMap::new())
        }

        async fn handle_finalized_block(
            &self,
            _dbtx: DatabaseTransaction<'_, '_>,
            _block_id: u32,
            _block_height: u32,
            _block_hash: bitcoin::BlockHash,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
    }

    async fn create_state_manager(
        config: &mut BridgeConfig,
    ) -> (JoinHandle<Result<(), eyre::Report>>, oneshot::Sender<()>) {
        let db = Database::new(config).await.unwrap();

        let state_manager = StateManager::new(
            db,
            MockHandler,
            ProtocolParamsetName::Regtest.into(),
            "test_consumer_handle".to_string(),
        )
        .await
        .unwrap();
        let (handle, shutdown) = run_state_manager(state_manager, Duration::from_millis(100)).await;
        (handle, shutdown)
    }

    #[tokio::test]
    async fn test_run_state_manager() {
        let mut config = create_test_config_with_thread_name(None).await;
        let (handle, shutdown) = create_state_manager(&mut config).await;

        drop(shutdown);

        timeout(Duration::from_secs(1), handle)
            .await
            .expect("state manager should exit after shutdown signal (timed out after 1s)")
            .expect("state manager should shutdown gracefully (thread panic should not happen)")
            .expect("state manager should shutdown gracefully");
    }

    #[tokio::test]
    async fn test_state_mgr_does_not_shutdown() {
        let mut config = create_test_config_with_thread_name(None).await;
        let (handle, shutdown) = create_state_manager(&mut config).await;

        timeout(Duration::from_secs(1), handle).await.expect_err(
            "state manager should not shutdown while shutdown handle is alive (timed out after 1s)",
        );

        drop(shutdown);
    }
}
