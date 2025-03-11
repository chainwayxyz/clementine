use crate::{bitcoin_syncer::BitcoinSyncerEvent, database::Database};
use eyre::{Context as _, OptionExt};
use pgmq::{Message, PGMQueueExt};
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{config::protocol::ProtocolParamset, errors::BridgeError, states::SystemEvent};

use super::{context::Owner, StateManager};

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    /// Starts a new task to periodically fetch new blocks from bitcoin_syncer
    pub async fn block_fetcher_task(
        last_processed_block_height: u32,
        db: Database,
        poll_delay: Duration,
        paramset: &'static ProtocolParamset,
    ) -> JoinHandle<Result<(), eyre::Report>> {
        tokio::spawn(async move {
            let queue_name = Self::queue_name();
            tracing::info!(
                "Starting state manager block syncing with owner type {} starting from height {}",
                T::OWNER_TYPE,
                last_processed_block_height
            );

            // variable to store locally last sent height
            let mut last_sent_height = last_processed_block_height;
            let mut num_consecutive_errors = 0;
            let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
            loop {
                let result: Result<bool, eyre::Report> = async {
                    let mut dbtx = db.begin_transaction().await?;
                    let did_find_new_block = async {
                        let Some(event) = db
                            .fetch_next_bitcoin_syncer_evt(&mut dbtx, &queue_name)
                            .await?
                        else {
                            return Ok::<bool, eyre::Report>(false);
                        };

                        Ok(match event {
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
                                    new_tip = true;

                                    let next_height = last_sent_height + 1;

                                    let block = db
                                        .get_full_block(Some(&mut dbtx), next_height)
                                        .await?
                                        .ok_or_eyre(format!(
                                            "Block at height {} not found",
                                            next_height
                                        ))?;

                                    let event = SystemEvent::NewBlock {
                                        block_id,
                                        block,
                                        height: next_height,
                                    };

                                    queue
                                        .send_with_cxn(&queue_name, &event, &mut *dbtx)
                                        .await
                                        .wrap_err("Error sending new block event to queue")?;

                                    last_sent_height += 1;
                                }

                                new_tip
                            }
                            BitcoinSyncerEvent::ReorgedBlock(_) => false,
                        })
                    }
                    .await?;

                    dbtx.commit().await?;

                    if did_find_new_block {
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
                            return Err(e.wrap_err(
                                "Too many consecutive state machine block fetching errors. Last error is included in the cause chain.",
                            ));
                        }
                        tokio::time::sleep(poll_delay).await;
                    }
                }
            }
        })
    }

    pub async fn into_msg_consumer_task(
        mut self,
        poll_delay: Duration,
    ) -> (JoinHandle<Result<(), eyre::Report>>, oneshot::Sender<()>)
    where
        T: Owner + std::fmt::Debug + 'static,
    {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let queue_name = StateManager::<T>::queue_name();
            tracing::info!(
                "Starting state manager main run thread with owner type {}",
                T::OWNER_TYPE
            );
            let db = self.db.clone();
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
                        let Some(new_event): Option<Message<SystemEvent>> = self
                            .queue
                            .read_with_cxn(&queue_name, 1, &mut *dbtx)
                            .await
                            .map_err(|e| {
                                BridgeError::Error(format!("Error reading event: {:?}", e))
                            })?
                        else {
                            dbtx.commit().await?;
                            return Ok::<bool, BridgeError>(false);
                        };

                        let event_id = new_event.msg_id;
                        self.handle_event(new_event.message, &mut dbtx).await?;
                        // handled event, delete it from queue
                        self.queue
                            .archive_with_cxn(&queue_name, event_id, &mut *dbtx)
                            .await
                            .map_err(|e| {
                                BridgeError::Error(format!("Error deleting event: {:?}", e))
                            })?;
                        dbtx.commit().await.map_err(|e| {
                            BridgeError::Error(format!("Error committing transaction: {:?}", e))
                        })?;
                        Ok(true)
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
                        // if num_consecutive_errors > 50 {
                        //     return Err(eyre::eyre!("Too many consecutive state machine errors"));
                        // }
                        tokio::time::sleep(poll_delay).await;
                    }
                }
            }
        });

        (handle, shutdown_tx)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::time::timeout;
    use tonic::async_trait;

    use crate::{
        builder::transaction::{ContractContext, TransactionType, TxHandler},
        config::{protocol::ProtocolParamsetName, BridgeConfig},
        database::DatabaseTransaction,
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
            _block: &bitcoin::Block,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
    }

    async fn create_state_manager(
        config: &mut BridgeConfig,
    ) -> (JoinHandle<Result<(), eyre::Report>>, oneshot::Sender<()>) {
        let db = Database::new(config).await.unwrap();

        let state_manager =
            StateManager::new(db, MockHandler, ProtocolParamsetName::Regtest.into())
                .await
                .unwrap();
        let (handle, shutdown) = state_manager
            .into_msg_consumer_task(Duration::from_millis(100))
            .await;
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
