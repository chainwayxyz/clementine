use super::{IntoTask, Task, TaskExt};
use crate::{errors::BridgeError, utils::NamedEntity};
use futures::future::join_all;
use std::{marker::PhantomData, time::Duration};
use tokio::{
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::sleep,
};

/// A background task manager that can hold and manage multiple tasks When
/// dropped, it will abort all tasks. Graceful shutdown can be performed with
/// `graceful_shutdown`
#[derive(Debug)]
pub struct BackgroundTaskManager<T: NamedEntity + 'static> {
    /// Task handles for spawned tasks
    abort_handles: Vec<AbortHandle>,
    /// Cancellation senders for tasks
    cancel_txs: Vec<oneshot::Sender<()>>,
    phantom: PhantomData<T>,
}

impl<T: NamedEntity + 'static> Default for BackgroundTaskManager<T> {
    fn default() -> Self {
        Self {
            abort_handles: Vec::new(),
            cancel_txs: Vec::new(),
            phantom: PhantomData,
        }
    }
}

impl<T: NamedEntity + 'static> BackgroundTaskManager<T> {
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

    /// Wraps the task in a cancelable loop and spawns it in the background with built-in monitoring.
    ///
    /// If required, polling should be added **before** a call to this function via `task.into_polling()`
    pub fn loop_and_monitor<S, U: IntoTask<Task = S>>(&mut self, task: U)
    where
        S: Task + Sized + std::fmt::Debug,
        <S as Task>::Output: Into<bool>,
    {
        let task = task.into_task();
        let task_name = format!("{:?}", task);
        let (task, cancel_tx) = task.cancelable_loop();

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
    /// This function does not have any timeout, please use
    /// `graceful_shutdown_with_timeout` instead for cases where you need a
    /// timeout. The function polls tasks until they are finished with a 100ms
    /// poll interval.
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

    /// Graceful shutdown of all tasks with a timeout. All tasks will be aborted
    /// if the timeout is reached.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration for the graceful shutdown. Since the
    ///   `graceful_shutdown` function polls tasks until they are finished with a
    ///   100ms poll interval, the timeout should be at least 100ms for the
    ///   timeout to be effective.
    pub async fn graceful_shutdown_with_timeout(&mut self, timeout: Duration) {
        let timeout_handle = tokio::time::timeout(timeout, self.graceful_shutdown());

        if timeout_handle.await.is_err() {
            self.abort_all();
        }
    }
}

impl<T: NamedEntity + 'static> Drop for BackgroundTaskManager<T> {
    fn drop(&mut self) {
        self.abort_all();
    }
}
