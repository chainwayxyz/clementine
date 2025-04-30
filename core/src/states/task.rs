use crate::{
    bitcoin_syncer::BitcoinSyncerEvent,
    database::Database,
    task::{BufferedErrors, IntoTask, WithDelay},
};
use eyre::Context as _;
use pgmq::{Message, PGMQueueExt};
use std::time::Duration;
use tonic::async_trait;

use crate::{
    config::protocol::ProtocolParamset,
    errors::BridgeError,
    states::SystemEvent,
    task::{Task, TaskExt},
};

use super::{context::Owner, StateManager};

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(1)
};

/// A task that fetches new blocks from Bitcoin and adds them to the state management queue
#[derive(Debug)]
pub struct BlockFetcherTask<T: Owner + std::fmt::Debug + 'static> {
    /// The database to fetch events from
    db: Database,
    /// Queue for sending events
    queue: PGMQueueExt,
    /// Queue name for this owner type
    queue_name: String,
    /// The next height to process
    next_height: u32,
    /// Protocol parameters
    paramset: &'static ProtocolParamset,
    /// Owner type marker
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Owner + std::fmt::Debug + 'static> BlockFetcherTask<T> {
    /// Creates a new block fetcher task
    pub async fn new(
        next_height: u32,
        db: Database,
        paramset: &'static ProtocolParamset,
    ) -> Result<Self, BridgeError> {
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let queue_name = StateManager::<T>::queue_name();

        tracing::info!(
            "Creating block fetcher task for owner type {} starting from height {}",
            T::OWNER_TYPE,
            next_height
        );

        Ok(Self {
            db,
            queue,
            queue_name,
            next_height,
            paramset,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[async_trait]
impl<T: Owner + std::fmt::Debug + 'static> Task for BlockFetcherTask<T> {
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await?;

        // Poll for the next bitcoin syncer event
        let Some(event) = self
            .db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.queue_name)
            .await?
        else {
            // No event found, we can safely commit the transaction and return
            dbtx.commit().await?;
            return Ok(false);
        };

        // Process the event
        let did_find_new_block = match event {
            BitcoinSyncerEvent::NewBlock(block_id) => {
                let current_tip_height = self
                    .db
                    .get_block_info_from_id(Some(&mut dbtx), block_id)
                    .await?
                    .ok_or(BridgeError::Error(
                        "Block not found in BlockFetcherTask".to_string(),
                    ))?
                    .1;
                let mut new_tip = false;

                // Update states to catch up to finalized chain
                while current_tip_height >= self.paramset.finality_depth
                    && self.next_height <= current_tip_height - self.paramset.finality_depth
                {
                    new_tip = true;

                    let block = self
                        .db
                        .get_full_block(Some(&mut dbtx), self.next_height)
                        .await?
                        .ok_or(BridgeError::Error(format!(
                            "Block at height {} not found in BlockFetcherTask, current tip height is {}",
                            self.next_height, current_tip_height
                        )))?;

                    let new_block_id = self
                        .db
                        .get_canonical_block_id_from_height(Some(&mut dbtx), self.next_height)
                        .await?;

                    if new_block_id.is_none() {
                        tracing::error!("Block at height {} not found in BlockFetcherTask, current tip height is {}", self.next_height, current_tip_height);
                        return Err(BridgeError::Error(format!(
                            "Block at height {} not found in BlockFetcherTask, current tip height is {}",
                            self.next_height, current_tip_height
                        )));
                    }

                    let event = SystemEvent::NewBlock {
                        block_id: new_block_id.expect("it must be some"),
                        block,
                        height: self.next_height,
                    };

                    self.queue
                        .send_with_cxn(&self.queue_name, &event, &mut *dbtx)
                        .await
                        .map_err(|e| {
                            BridgeError::Error(format!(
                                "Error sending new block event to queue: {:?}",
                                e
                            ))
                        })?;

                    self.next_height += 1;
                }

                new_tip
            }
            BitcoinSyncerEvent::ReorgedBlock(_) => false,
        };

        dbtx.commit().await?;
        // Return whether we found new blocks
        Ok(did_find_new_block)
    }
}

#[derive(Debug)]
pub struct MessageConsumerTask<T: Owner + std::fmt::Debug + 'static> {
    db: Database,
    inner: StateManager<T>,
    /// Queue name for this owner type (cached)
    queue_name: String,
}

#[async_trait]
impl<T: Owner + std::fmt::Debug + 'static> Task for MessageConsumerTask<T> {
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let new_event_received = async {
            let mut dbtx = self.db.begin_transaction().await?;

            // Poll new event
            let Some(Message {
                msg_id, message, ..
            }): Option<Message<SystemEvent>> = self
                .inner
                .queue
                // 2nd param of read_with_cxn is the visibility timeout, set to 0 as we only have 1 consumer of the queue, which is the state machine
                .read_with_cxn(&self.queue_name, 0, &mut *dbtx)
                .await
                .wrap_err("Reading event from queue")?
            else {
                dbtx.commit().await?;
                return Ok::<_, BridgeError>(false);
            };

            self.inner.handle_event(message, &mut dbtx).await?;

            // Delete event from queue
            self.inner
                .queue
                .archive_with_cxn(&self.queue_name, msg_id, &mut *dbtx)
                .await
                .wrap_err("Deleting event from queue")?;

            dbtx.commit().await?;
            Ok(true)
        }
        .await?;

        Ok(new_event_received)
    }
}

impl<T: Owner + std::fmt::Debug + 'static> IntoTask for StateManager<T> {
    type Task = WithDelay<BufferedErrors<MessageConsumerTask<T>>>;

    /// Converts the StateManager into the consumer task with a delay
    fn into_task(self) -> Self::Task {
        MessageConsumerTask {
            db: self.db.clone(),
            inner: self,
            queue_name: StateManager::<T>::queue_name(),
        }
        .into_buffered_errors(50)
        .with_delay(POLL_DELAY)
    }
}

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    pub async fn block_fetcher_task(&self) -> Result<WithDelay<BlockFetcherTask<T>>, BridgeError> {
        Ok(
            BlockFetcherTask::<T>::new(self.next_height_to_process, self.db.clone(), self.paramset)
                .await?
                .with_delay(POLL_DELAY),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use tokio::{sync::oneshot, task::JoinHandle, time::timeout};
    use tonic::async_trait;

    use crate::{
        builder::transaction::{ContractContext, TransactionType, TxHandler},
        config::{protocol::ProtocolParamsetName, BridgeConfig},
        database::DatabaseTransaction,
        states::{block_cache, context::DutyResult, Duty},
        test::common::create_test_config_with_thread_name,
    };

    use super::*;

    #[derive(Clone, Debug)]
    struct MockHandler;

    #[async_trait]
    impl Owner for MockHandler {
        const OWNER_TYPE: &'static str = "MockHandler";

        async fn handle_duty(&self, _: Duty) -> Result<DutyResult, BridgeError> {
            Ok(DutyResult::Handled)
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
            _block_cache: Arc<block_cache::BlockCache>,
            _light_client_proof_wait_interval_secs: Option<u32>,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
    }

    async fn create_state_manager(
        config: &mut BridgeConfig,
    ) -> (JoinHandle<Result<(), BridgeError>>, oneshot::Sender<()>) {
        let db = Database::new(config).await.unwrap();

        let state_manager =
            StateManager::new(db, MockHandler, ProtocolParamsetName::Regtest.into())
                .await
                .unwrap();
        let (t, shutdown) = state_manager.into_task().cancelable_loop();
        (t.into_bg(), shutdown)
    }

    #[tokio::test]
    async fn test_run_state_manager() {
        let mut config = create_test_config_with_thread_name().await;
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
        let mut config = create_test_config_with_thread_name().await;
        let (handle, shutdown) = create_state_manager(&mut config).await;

        timeout(Duration::from_secs(1), handle).await.expect_err(
            "state manager should not shutdown while shutdown handle is alive (timed out after 1s)",
        );

        drop(shutdown);
    }
}
