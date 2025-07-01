use super::status_monitor::{TaskStatusMonitorTask, TASK_STATUS_MONITOR_POLL_DELAY};
use super::{IntoTask, Task, TaskExt, TaskVariant};
use crate::errors::BridgeError;
use crate::rpc::clementine::StoppedTasks;
use crate::utils::NamedEntity;
use futures::future::join_all;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, RwLock};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::sleep;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaskStatus {
    Running,
    NotRunning(String),
}

pub type TaskRegistry =
    HashMap<TaskVariant, (TaskStatus, AbortHandle, Option<oneshot::Sender<()>>)>;

/// A background task manager that can hold and manage multiple tasks When
/// dropped, it will abort all tasks. Graceful shutdown can be performed with
/// `graceful_shutdown`
#[derive(Debug)]
pub struct BackgroundTaskManager<T: NamedEntity + Send + 'static> {
    pub(crate) task_registry: Arc<RwLock<TaskRegistry>>,
    phantom: PhantomData<T>,
}

impl<T: NamedEntity + Send + 'static> Default for BackgroundTaskManager<T> {
    fn default() -> Self {
        Self {
            task_registry: Arc::new(RwLock::new(HashMap::new())),
            phantom: PhantomData,
        }
    }
}

impl<T: NamedEntity + Send + 'static> BackgroundTaskManager<T> {
    fn monitor_spawned_task(
        &self,
        handle: JoinHandle<Result<(), BridgeError>>,
        task_variant: TaskVariant,
        task_registry: Arc<RwLock<TaskRegistry>>,
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

            let mut task_registry = task_registry.write().await;
            let current_status = task_registry.remove(&task_variant);
            match current_status {
                Some((_, abort_handle, cancel_tx)) => {
                    task_registry.insert(
                        task_variant,
                        (TaskStatus::NotRunning(exit_reason), abort_handle, cancel_tx),
                    );
                }
                _ => {}
            }
        });
    }

    /// Checks if a task is running
    async fn is_task_running(&self, variant: TaskVariant) -> bool {
        self.task_registry
            .read()
            .await
            .get(&variant)
            .map(|(status, _, _)| status == &TaskStatus::Running)
            .unwrap_or(false)
    }

    pub async fn get_stopped_tasks(&self) -> StoppedTasks {
        let mut stopped_tasks = vec![];
        let task_registry = self.task_registry.read().await;
        for (variant, (status, _, _)) in task_registry.iter() {
            match status {
                TaskStatus::Running => {}
                TaskStatus::NotRunning(reason) => {
                    stopped_tasks.push(format!("{:?}: {}", variant, reason));
                }
            }
        }
        StoppedTasks { stopped_tasks }
    }

    pub async fn get_task_status(&self, variant: TaskVariant) -> Option<TaskStatus> {
        self.task_registry
            .read()
            .await
            .get(&variant)
            .map(|(status, _, _)| status.clone())
    }

    /// Wraps the task in a cancelable loop and spawns it, registers it in the task registry.
    async fn start_and_register_task<S, U: IntoTask<Task = S>>(&self, task: U)
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
        if self.is_task_running(variant).await {
            tracing::debug!("Task {:?} is already running, skipping", variant);
            return;
        }

        self.monitor_spawned_task(bg_task, variant, self.task_registry.clone());

        self.task_registry.write().await.insert(
            variant,
            (TaskStatus::Running, abort_handle, Some(cancel_tx)),
        );
    }

    /// Wraps the task in a cancelable loop and spawns it in the background with built-in monitoring.
    ///
    /// If required, polling should be added **before** a call to this function via `task.into_polling()`
    pub async fn loop_and_monitor<S, U: IntoTask<Task = S>>(&self, task: U)
    where
        S: Task + Sized + std::fmt::Debug,
        <S as Task>::Output: Into<bool>,
    {
        self.start_and_register_task(task).await;

        // start the monitoring task if it is not running
        if !self.is_task_running(TaskVariant::TaskStatusMonitor).await {
            self.start_and_register_task(
                TaskStatusMonitorTask::new(self.task_registry.clone())
                    .with_delay(TASK_STATUS_MONITOR_POLL_DELAY),
            )
            .await;
        }
    }

    /// Sends cancel signals to all tasks that have a cancel_tx
    async fn send_cancel_signals(&self) {
        let mut task_registry = self.task_registry.write().await;
        for (variant, (status, abort_handle, cancel_tx)) in task_registry.iter_mut() {
            let oneshot_tx = cancel_tx.take();
            if let Some(oneshot_tx) = oneshot_tx {
                oneshot_tx.send(());
            }
        }
    }

    /// Abort all tasks by dropping their cancellation senders
    pub fn abort_all(&mut self) {
        // only one thread must have &mut self, so lock should be able to be acquired
        if let Ok(task_registry) = self.task_registry.try_read() {
            for (_, (_, abort_handle, cancel_tx)) in task_registry.iter() {
                abort_handle.abort();
            }
            return;
        }
    }

    /// Graceful shutdown of all tasks
    ///
    /// This function does not have any timeout, please use
    /// `graceful_shutdown_with_timeout` instead for cases where you need a
    /// timeout. The function polls tasks until they are finished with a 100ms
    /// poll interval.
    pub async fn graceful_shutdown(&mut self) {
        self.send_cancel_signals().await;

        let mut task_registry = self.task_registry.write().await;
        join_all(task_registry.iter_mut().map(
            |(variant, (status, abort_handle, cancel_tx))| async move {
                loop {
                    if abort_handle.is_finished() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            },
        ))
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
