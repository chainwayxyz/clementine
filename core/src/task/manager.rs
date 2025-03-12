use futures::future::join_all;
use std::marker::PhantomData;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::sleep;

use crate::errors::BridgeError;
use crate::states::Owner;

use super::{Task, TaskExt};
/// A background task manager that can hold and manage multiple tasks When
/// dropped, it will abort all tasks. Graceful shutdown can be performed with
/// `graceful_shutdown`
pub struct BackgroundTaskManager<T: Owner + 'static> {
    /// Task handles for spawned tasks
    abort_handles: Vec<AbortHandle>,
    /// Cancellation senders for tasks
    cancel_txs: Vec<oneshot::Sender<()>>,
    phantom: PhantomData<T>,
}

impl<T: Owner + 'static> BackgroundTaskManager<T> {
    /// Create a new empty task manager
    pub fn new() -> Self {
        BackgroundTaskManager {
            abort_handles: Vec::new(),
            cancel_txs: Vec::new(),
            phantom: PhantomData,
        }
    }

    fn monitor_spawned_task(&self, handle: JoinHandle<Result<(), BridgeError>>, task_name: String) {
        tokio::spawn(async move {
            match handle.await {
                Ok(Ok(_)) => {
                    // Task completed successfully
                    tracing::debug!("Task {} completed successfully", task_name);
                }
                Ok(Err(e)) => {
                    // Task returned an error
                    tracing::error!("Task {} failed with error: {:?}", task_name, e);
                }
                Err(e) => {
                    if e.is_cancelled() {
                        // Task was cancelled, which is expected during cleanup
                        tracing::debug!("Task {} was cancelled", task_name);
                        return;
                    }
                    // Task panicked or was aborted
                    tracing::error!("Task {} panicked: {:?}", task_name, e);
                }
            }
        });
    }

    /// Add a task to the manager with automatic polling
    pub fn run_and_monitor<U: Task + Sized + std::fmt::Debug>(&mut self, task: U)
    where
        U::Output: Into<bool>,
    {
        let task_name = format!("{:?}", task);
        let (task, cancel_tx) = task.into_loop();

        let bg_task = task.into_bg();
        let abort_handle = bg_task.abort_handle();

        self.monitor_spawned_task(bg_task, task_name);

        self.abort_handles.push(abort_handle);
        self.cancel_txs.push(cancel_tx);
    }

    /// Abort all tasks by dropping their cancellation senders
    pub fn abort_all(&mut self) {
        // Dropping the cancel_txs will trigger cancellation
        self.cancel_txs.clear();

        // Also abort the tasks directly for immediate effect
        for handle in &self.abort_handles {
            handle.abort();
        }

        self.abort_handles.clear();
    }

    /// Graceful shutdown of all tasks
    ///
    /// This function does not have any timeout, please use `graceful_shutdown_with_timeout` instead for cases where you need a timeout.
    pub async fn graceful_shutdown(&mut self) {
        self.cancel_txs.clear();

        let handles = std::mem::take(&mut self.abort_handles);

        join_all(handles.into_iter().map(|handle| async move {
            loop {
                if handle.is_finished() {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
        }))
        .await;
    }

    /// Graceful shutdown of all tasks with a timeout. All tasks will be aborted if the timeout is reached.
    pub async fn graceful_shutdown_with_timeout(&mut self, timeout: Duration) {
        let timeout_handle = tokio::time::timeout(timeout, self.graceful_shutdown());
        match timeout_handle.await {
            Ok(_) => {}
            Err(_) => {
                self.abort_all();
            }
        }
    }
}

impl<T: Owner + 'static> Drop for BackgroundTaskManager<T> {
    fn drop(&mut self) {
        self.abort_all();
    }
}
