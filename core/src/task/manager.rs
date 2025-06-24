use super::{IntoTask, Task, TaskExt, TaskVariant};
use crate::errors::BridgeError;
use crate::utils::NamedEntity;
use futures::future::join_all;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::sleep;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaskStatus {
    Running,
    NotRunning(String),
}

/// A background task manager that can hold and manage multiple tasks When
/// dropped, it will abort all tasks. Graceful shutdown can be performed with
/// `graceful_shutdown`
#[derive(Debug)]
pub struct BackgroundTaskManager<T: NamedEntity + Send + 'static> {
    /// Task handles for spawned tasks
    abort_handles: HashMap<TaskVariant, AbortHandle>,
    /// Cancellation senders for tasks
    cancel_txs: HashMap<TaskVariant, oneshot::Sender<()>>,
    pub(crate) tasks_status: HashMap<TaskVariant, TaskStatus>,
    phantom: PhantomData<T>,
}

impl<T: NamedEntity + Send + 'static> Default for BackgroundTaskManager<T> {
    fn default() -> Self {
        Self {
            abort_handles: HashMap::new(),
            cancel_txs: HashMap::new(),
            tasks_status: HashMap::new(),
            phantom: PhantomData,
        }
    }
}

impl<T: NamedEntity + Send + 'static> BackgroundTaskManager<T> {
    fn monitor_spawned_task(
        &self,
        handle: JoinHandle<Result<(), BridgeError>>,
        task_variant: TaskVariant,
        tasks: Arc<Mutex<Self>>,
    ) {
        tokio::spawn(async move {
            let exit_reason = match handle.await {
                Ok(Ok(_)) => {
                    // Task completed successfully
                    tracing::debug!("Task {:?} completed successfully", task_variant);
                    "Completed successfully".to_string()
                }
                Ok(Err(e)) => {
                    // Task returned an error
                    tracing::error!("Task {:?} failed with error: {:?}", task_variant, e);
                    format!("Failed due to error: {:?}", e)
                }
                Err(e) => {
                    if e.is_cancelled() {
                        // Task was cancelled, which is expected during cleanup
                        tracing::debug!("Task {:?} was cancelled", task_variant);
                        "Cancelled".to_string()
                    } else {
                        // Task panicked or was aborted
                        tracing::error!("Task {:?} panicked: {:?}", task_variant, e);
                        format!("Panicked due to {:?}", e)
                    }
                }
            };

            let mut tasks = tasks.lock().await;
            tasks
                .tasks_status
                .insert(task_variant, TaskStatus::NotRunning(exit_reason));
        });
    }

    /// Checks if a task is running
    fn is_task_running(&self, variant: TaskVariant) -> bool {
        self.tasks_status
            .get(&variant)
            .unwrap_or(&TaskStatus::NotRunning("".to_string()))
            == &TaskStatus::Running
    }

    pub fn get_task_status(&self, variant: TaskVariant) -> Option<TaskStatus> {
        self.tasks_status.get(&variant).cloned()
    }

    /// Wraps the task in a cancelable loop and spawns it in the background with built-in monitoring.
    ///
    /// If required, polling should be added **before** a call to this function via `task.into_polling()`
    pub fn loop_and_monitor<S, U: IntoTask<Task = S>>(&mut self, task: U, tasks: Arc<Mutex<Self>>)
    where
        S: Task + Sized + std::fmt::Debug,
        <S as Task>::Output: Into<bool>,
    {
        let task = task.into_task();
        let (task, cancel_tx) = task.cancelable_loop();

        let bg_task = task.into_bg();
        let abort_handle = bg_task.abort_handle();

        let variant = S::VARIANT;

        // do not start the same task if it is already running
        if self.is_task_running(variant) {
            tracing::debug!("Task {:?} is already running, skipping", variant);
            return;
        }

        self.monitor_spawned_task(bg_task, variant, tasks);

        self.abort_handles.insert(variant, abort_handle);
        self.cancel_txs.insert(variant, cancel_tx);
        self.tasks_status.insert(variant, TaskStatus::Running);
    }

    /// Abort all tasks by dropping their cancellation senders
    pub fn abort_all(&mut self) {
        // Dropping the cancel_txs will trigger cancellation
        self.cancel_txs.clear();

        // Also abort the tasks directly for immediate effect
        for (variant, handle) in &self.abort_handles {
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

        join_all(handles.into_iter().map(|(variant, handle)| async move {
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

impl<T: NamedEntity + Send + 'static> Drop for BackgroundTaskManager<T> {
    fn drop(&mut self) {
        self.abort_all();
    }
}
