use crate::{
    database::Database,
    finalized_block_fetcher::FinalizedBlockCursor,
    task::{BufferedErrors, IntoTask, RecoverableTask, TaskVariant, WithDelay},
};
use eyre::{Context as _, OptionExt};
use pgmq::Message;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tonic::async_trait;

use crate::{
    states::SystemEvent,
    task::{Task, TaskExt},
};
use clementine_errors::BridgeError;

use super::{context::Owner, StateManager};

type SharedDatabaseTransaction = Arc<Mutex<sqlx::Transaction<'static, sqlx::Postgres>>>;

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(30)
};

/// A task that reads new events from the message queue and processes them.
#[derive(Debug)]
pub struct MessageConsumerTask<T: Owner + std::fmt::Debug + 'static> {
    db: Database,
    inner: StateManager<T>,
    /// Queue name for this owner type (cached)
    queue_name: String,
    finalized_block_cursor: FinalizedBlockCursor,
    cursor_progress_seeded: bool,
}

#[async_trait]
impl<T: Owner + std::fmt::Debug + 'static> Task for MessageConsumerTask<T> {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::StateManager;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        self.ensure_cursor_progress_seeded().await?;

        if self.process_queue_event_once().await? {
            return Ok(true);
        }

        self.process_finalized_block_once().await
    }
}

#[async_trait]
impl<T: Owner + std::fmt::Debug + 'static> RecoverableTask for MessageConsumerTask<T> {
    async fn recover_from_error(&mut self, _error: &BridgeError) -> Result<(), BridgeError> {
        // in case of any error, reload the state machines from the database
        self.inner.reload_state_manager_from_db().await?;
        self.finalized_block_cursor
            .reset_to_last_processed_height(self.last_processed_height());
        self.cursor_progress_seeded = false;
        Ok(())
    }
}

impl<T: Owner + std::fmt::Debug + 'static> MessageConsumerTask<T> {
    fn last_processed_height(&self) -> Option<u32> {
        self.inner.get_next_height_to_process().checked_sub(1)
    }

    async fn ensure_cursor_progress_seeded(&mut self) -> Result<(), BridgeError> {
        if self.cursor_progress_seeded {
            return Ok(());
        }

        self.finalized_block_cursor
            .reconcile_progress_with_current_height(self.last_processed_height())
            .await?;
        self.cursor_progress_seeded = true;
        Ok(())
    }

    async fn process_queue_event_once(&mut self) -> Result<bool, BridgeError> {
        tracing::trace!(queue = %self.queue_name, "MessageConsumerTask: begin_transaction");
        let mut dbtx = self.db.begin_transaction().await?;
        tracing::trace!(queue = %self.queue_name, "MessageConsumerTask: begin_transaction done, reading queue");

        let Some(Message {
            msg_id, message, ..
        }): Option<Message<SystemEvent>> = self
            .inner
            .queue
            .read_with_cxn(&self.queue_name, 0, &mut *dbtx)
            .await
            .wrap_err("Reading event from queue")?
        else {
            dbtx.commit().await?;
            return Ok(false);
        };

        tracing::trace!(
            queue = %self.queue_name,
            msg_id,
            event = ?message,
            "MessageConsumerTask: read event from queue, starting handle_event"
        );
        let handle_start = std::time::Instant::now();

        let arc_dbtx = Arc::new(Mutex::new(dbtx));

        self.inner.handle_event(message, arc_dbtx.clone()).await?;

        tracing::trace!(
            queue = %self.queue_name,
            msg_id,
            elapsed_ms = handle_start.elapsed().as_millis() as u64,
            "MessageConsumerTask: handle_event done, extracting dbtx"
        );

        let mut dbtx = unwrap_shared_dbtx(arc_dbtx)?;

        self.inner
            .queue
            .archive_with_cxn(&self.queue_name, msg_id, &mut *dbtx)
            .await
            .wrap_err("Deleting event from queue")?;

        tracing::trace!(
            queue = %self.queue_name,
            msg_id,
            "MessageConsumerTask: committing transaction"
        );
        dbtx.commit().await?;
        tracing::trace!(
            queue = %self.queue_name,
            msg_id,
            total_elapsed_ms = handle_start.elapsed().as_millis() as u64,
            "MessageConsumerTask: committed successfully"
        );
        Ok(true)
    }

    async fn process_finalized_block_once(&mut self) -> Result<bool, BridgeError> {
        let Some((height, block)) = self.finalized_block_cursor.next_finalized_block().await?
        else {
            return Ok(false);
        };

        let block_hash = block.block_hash();
        let dbtx = self.db.begin_transaction().await?;
        let arc_dbtx = Arc::new(Mutex::new(dbtx));

        self.inner
            .handle_finalized_block(block, height, arc_dbtx.clone())
            .await?;

        let mut dbtx = unwrap_shared_dbtx(arc_dbtx)?;

        self.finalized_block_cursor
            .save_progress(&mut dbtx, height)
            .await?;
        dbtx.commit().await?;
        self.finalized_block_cursor
            .record_processed(height, block_hash);
        Ok(true)
    }
}

fn unwrap_shared_dbtx(
    dbtx: SharedDatabaseTransaction,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, BridgeError> {
    Ok(Arc::into_inner(dbtx)
        .ok_or_eyre("Expected single reference to DB tx when committing")?
        .into_inner())
}

impl<T: Owner + std::fmt::Debug + 'static> StateManager<T> {
    async fn handle_finalized_block(
        &mut self,
        block: bitcoin::Block,
        height: u32,
        dbtx: SharedDatabaseTransaction,
    ) -> Result<(), BridgeError> {
        let event_start = std::time::Instant::now();
        tracing::trace!(height, "handle_finalized_block: starting");

        if self.get_next_height_to_process() != height {
            return Err(eyre::eyre!("Finalized block arrived to state manager out of order. Expected: block at height {}, Got: block at height {}", self.get_next_height_to_process(), height).into());
        }

        let mut context = self.new_context(dbtx, &block, height)?;
        self.process_block_parallel(&mut context).await?;
        self.last_finalized_block = Some(context.cache.clone());

        tracing::trace!(
            height,
            elapsed_ms = event_start.elapsed().as_millis() as u64,
            "handle_finalized_block: processed block"
        );

        let save_start = std::time::Instant::now();
        self.save_state_to_db(&mut context).await?;
        tracing::trace!(
            elapsed_ms = save_start.elapsed().as_millis() as u64,
            total_elapsed_ms = event_start.elapsed().as_millis() as u64,
            "handle_finalized_block: saved state"
        );

        Ok(())
    }
}

impl<T: Owner + std::fmt::Debug + 'static> IntoTask for StateManager<T> {
    type Task = WithDelay<BufferedErrors<MessageConsumerTask<T>>>;

    /// Converts the StateManager into the consumer task with a polling delay.
    fn into_task(self) -> Self::Task {
        let finalized_block_cursor = FinalizedBlockCursor::from_last_processed_height(
            self.db.clone(),
            self.rpc.clone(),
            T::FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION.to_string(),
            self.config.protocol_paramset,
            self.get_next_height_to_process().checked_sub(1),
        );

        MessageConsumerTask {
            db: self.db.clone(),
            inner: self,
            queue_name: StateManager::<T>::queue_name(),
            finalized_block_cursor,
            cursor_progress_seeded: false,
        }
        .into_buffered_errors(10, 3, Duration::from_secs(10))
        .with_delay(POLL_DELAY)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::{sync::oneshot, task::JoinHandle, time::timeout};
    use tonic::async_trait;

    use crate::{
        builder::transaction::{ContractContext, TxHandler},
        config::BridgeConfig,
        database::{Database, DatabaseTransaction},
        extended_bitcoin_rpc::ExtendedBitcoinRpc,
        states::{context::DutyResult, Duty},
        test::common::{
            create_regtest_rpc, create_test_config_with_thread_name, set_test_protocol_paramset,
        },
        utils::NamedEntity,
    };
    use clementine_primitives::TransactionType;

    use super::*;

    #[derive(Clone, Debug)]
    struct MockHandler;

    impl NamedEntity for MockHandler {
        const ENTITY_NAME: &'static str = "MockHandler";
        const LCP_SYNCER_CONSUMER_ID: &'static str = "mock_lcp_syncer";
        const FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION: &'static str =
            "mock_finalized_block_automation";
    }

    #[async_trait]
    impl Owner for MockHandler {
        async fn handle_duty(
            &self,
            _dbtx: DatabaseTransaction<'_>,
            _: Duty,
        ) -> Result<DutyResult, BridgeError> {
            Ok(DutyResult::Handled)
        }

        async fn create_txhandlers(
            &self,
            _dbtx: DatabaseTransaction<'_>,
            _: TransactionType,
            _: ContractContext,
        ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
            Ok(BTreeMap::new())
        }
    }

    async fn create_mock_state_manager(
        config: &BridgeConfig,
    ) -> (Database, StateManager<MockHandler>) {
        let db = Database::new(config).await.unwrap();
        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await
        .expect("Failed to connect to Bitcoin RPC");

        let state_manager = StateManager::new(db.clone(), MockHandler, rpc, config.clone())
            .await
            .unwrap();
        (db, state_manager)
    }

    async fn create_state_manager(
        config: &BridgeConfig,
    ) -> (JoinHandle<Result<(), BridgeError>>, oneshot::Sender<()>) {
        let (_, state_manager) = create_mock_state_manager(config).await;
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
        let (handle, shutdown) = create_state_manager(&config).await;

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
        let (handle, shutdown) = create_state_manager(&config).await;

        timeout(Duration::from_secs(1), handle).await.expect_err(
            "state manager should not shutdown while shutdown handle is alive (timed out after 1s)",
        );

        drop(shutdown);
    }

    #[tokio::test]
    async fn state_manager_processes_finalized_block_directly_when_queue_empty() {
        let mut config = create_test_config_with_thread_name().await;
        set_test_protocol_paramset(&mut config, 1, 1);
        let cleanup = create_regtest_rpc(&mut config).await;
        cleanup.rpc().mine_blocks(2).await.unwrap();
        let (db, state_manager) = create_mock_state_manager(&config).await;
        let mut task = state_manager.into_task();

        task.run_once().await.unwrap();

        assert_eq!(
            db.get_next_height_to_process(None, MockHandler::ENTITY_NAME)
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            db.get_finalized_block_progress(
                None,
                MockHandler::FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION
            )
            .await
            .unwrap()
            .map(|progress| progress.last_processed_height),
            Some(1)
        );
    }
}
