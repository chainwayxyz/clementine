use crate::{
    bitcoin_syncer::{BlockHandler, FinalizedBlockFetcherTask},
    database::{Database, DatabaseTransaction},
    task::{BufferedErrors, IntoTask, RecoverableTask, TaskVariant, WithDelay},
};
use eyre::{Context as _, OptionExt};
use pgmq::{Message, PGMQueueExt};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tonic::async_trait;

use crate::{
    config::protocol::ProtocolParamset,
    errors::BridgeError,
    states::SystemEvent,
    task::{Task, TaskExt},
};

use super::{context::Owner, StateManager};

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(30)
};

/// Block handler that sends events to a PostgreSQL message queue
#[derive(Debug, Clone)]
pub struct QueueBlockHandler {
    queue: PGMQueueExt,
    queue_name: String,
}

#[async_trait]
impl BlockHandler for QueueBlockHandler {
    /// Handles a new block by sending a new block event to the queue.
    /// State manager will process the block after reading the event from the queue.
    async fn handle_new_block(
        &mut self,
        dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block: bitcoin::Block,
        height: u32,
    ) -> Result<(), BridgeError> {
        let event = SystemEvent::NewFinalizedBlock {
            block_id,
            block,
            height,
        };

        self.queue
            .send_with_cxn(&self.queue_name, &event, &mut **dbtx)
            .await
            .wrap_err("Error sending new block event to queue")?;
        Ok(())
    }
}

/// A task that fetches new finalized blocks from Bitcoin and adds them to the state management queue
#[derive(Debug)]
pub struct BlockFetcherTask<T: Owner + std::fmt::Debug + 'static> {
    /// Owner type marker
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Owner + std::fmt::Debug + 'static> BlockFetcherTask<T> {
    /// Creates a new finalized block fetcher task that sends new finalized blocks to the message queue.
    pub async fn new_finalized_block_fetcher_task(
        db: Database,
        paramset: &'static ProtocolParamset,
    ) -> Result<FinalizedBlockFetcherTask<QueueBlockHandler>, BridgeError> {
        let queue = PGMQueueExt::new_with_pool(db.get_pool()).await;
        let queue_name = StateManager::<T>::queue_name();

        let handler = QueueBlockHandler {
            queue,
            queue_name: queue_name.clone(),
        };

        // get the next finalized block height to start from
        let next_height = db
            .get_next_finalized_block_height_for_consumer(
                None,
                T::FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION,
                paramset,
            )
            .await?;

        tracing::info!(
            "Creating block fetcher task for owner type {} starting from height {}",
            T::ENTITY_NAME,
            next_height
        );

        Ok(crate::bitcoin_syncer::FinalizedBlockFetcherTask::new(
            db,
            T::FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION.to_string(),
            paramset,
            next_height,
            handler,
        ))
    }
}

/// A task that reads new events from the message queue and processes them.
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
    const VARIANT: TaskVariant = TaskVariant::StateManager;

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
                // visibility timeout is the time after which the message is visible again to other consumers
                .read_with_cxn(&self.queue_name, 0, &mut *dbtx)
                .await
                .wrap_err("Reading event from queue")?
            else {
                dbtx.commit().await?;
                return Ok::<_, BridgeError>(false);
            };

            let arc_dbtx = Arc::new(Mutex::new(dbtx));

            self.inner.handle_event(message, arc_dbtx.clone()).await?;

            let mut dbtx = Arc::into_inner(arc_dbtx)
                .ok_or_eyre("Expected single reference to DB tx when committing")?
                .into_inner();

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

#[async_trait]
impl<T: Owner + std::fmt::Debug + 'static> RecoverableTask for MessageConsumerTask<T> {
    async fn recover_from_error(&mut self, _error: &BridgeError) -> Result<(), BridgeError> {
        // in case of any error, reload the state machines from the database
        self.inner.reload_state_manager_from_db().await
    }
}

impl<T: Owner + std::fmt::Debug + 'static> IntoTask for StateManager<T> {
    type Task = WithDelay<BufferedErrors<MessageConsumerTask<T>>>;

    /// Converts the StateManager into the consumer task with a polling delay.
    fn into_task(self) -> Self::Task {
        MessageConsumerTask {
            db: self.db.clone(),
            inner: self,
            queue_name: StateManager::<T>::queue_name(),
        }
        .into_buffered_errors(10, 3, Duration::from_secs(10))
        .with_delay(POLL_DELAY)
    }
}

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    pub async fn block_fetcher_task(
        &self,
    ) -> Result<WithDelay<impl Task<Output = bool> + std::fmt::Debug>, BridgeError> {
        Ok(BlockFetcherTask::<T>::new_finalized_block_fetcher_task(
            self.db.clone(),
            self.config.protocol_paramset,
        )
        .await?
        .into_buffered_errors(20, 3, Duration::from_secs(10))
        .with_delay(POLL_DELAY))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use tokio::{sync::oneshot, task::JoinHandle, time::timeout};
    use tonic::async_trait;

    use crate::{
        builder::transaction::{ContractContext, TransactionType, TxHandler},
        config::BridgeConfig,
        database::DatabaseTransaction,
        extended_bitcoin_rpc::ExtendedBitcoinRpc,
        states::{block_cache, context::DutyResult, Duty},
        test::common::{create_regtest_rpc, create_test_config_with_thread_name},
        utils::NamedEntity,
    };

    use super::*;

    #[derive(Clone, Debug)]
    struct MockHandler;

    impl NamedEntity for MockHandler {
        const ENTITY_NAME: &'static str = "MockHandler";
        const TX_SENDER_CONSUMER_ID: &'static str = "mock_tx_sender";
        const FINALIZED_BLOCK_CONSUMER_ID_NO_AUTOMATION: &'static str =
            "mock_finalized_block_no_automation";
        const FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION: &'static str =
            "mock_finalized_block_automation";
    }

    #[async_trait]
    impl Owner for MockHandler {
        async fn handle_duty(
            &self,
            _dbtx: DatabaseTransaction<'_, '_>,
            _: Duty,
        ) -> Result<DutyResult, BridgeError> {
            Ok(DutyResult::Handled)
        }

        async fn create_txhandlers(
            &self,
            _dbtx: DatabaseTransaction<'_, '_>,
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

        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await
        .expect("Failed to connect to Bitcoin RPC");

        let state_manager = StateManager::new(db, MockHandler, rpc, config.clone())
            .await
            .unwrap();
        let (t, shutdown) = state_manager.into_task().cancelable_loop();
        (t.into_bg(), shutdown)
    }

    #[tokio::test]
    async fn test_run_state_manager() {
        let mut config = create_test_config_with_thread_name().await;
        let cleanup = create_regtest_rpc(&mut config).await;
        cleanup
            .rpc()
            .mine_blocks(config.protocol_paramset.start_height as u64)
            .await
            .unwrap();
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
        let cleanup = create_regtest_rpc(&mut config).await;
        cleanup
            .rpc()
            .mine_blocks(config.protocol_paramset.start_height as u64)
            .await
            .unwrap();
        let (handle, shutdown) = create_state_manager(&mut config).await;

        timeout(Duration::from_secs(1), handle).await.expect_err(
            "state manager should not shutdown while shutdown handle is alive (timed out after 1s)",
        );

        drop(shutdown);
    }
}
