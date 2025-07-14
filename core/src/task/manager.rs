use super::status_monitor::{TaskStatusMonitorTask, TASK_STATUS_MONITOR_POLL_DELAY};
use super::{IntoTask, Task, TaskExt, TaskVariant};
use crate::errors::BridgeError;
use crate::rpc::clementine::StoppedTasks;
use crate::utils::timed_try_join_all;
use futures::future::join_all;
use std::collections::HashMap;
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

/// A background task manager that can hold and manage multiple tasks. When
/// dropped, it will abort all tasks. Graceful shutdown can be performed with
/// `graceful_shutdown`
#[derive(Debug)]
pub struct BackgroundTaskManager {
    task_registry: Arc<RwLock<TaskRegistry>>,
}

impl Default for BackgroundTaskManager {
    fn default() -> Self {
        Self {
            task_registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl BackgroundTaskManager {
    /// Monitors the spawned task. If any task stops running, logs the reason
    /// why and updates the task registry to register the task as not running.
    fn monitor_spawned_task(
        &self,
        handle: JoinHandle<Result<(), BridgeError>>,
        task_variant: TaskVariant,
    ) {
        let task_registry = Arc::downgrade(&self.task_registry);

        tokio::spawn(async move {
            let exit_reason = match handle.await {
                Ok(Ok(_)) => {
                    // Task completed successfully
                    tracing::debug!("Task {:?} completed successfully", task_variant);
                    "Completed successfully".to_owned()
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
                        "Cancelled".to_owned()
                    } else {
                        // Task panicked or was aborted
                        tracing::error!("Task {:?} panicked: {:?}", task_variant, e);
                        format!("Panicked due to {:?}", e)
                    }
                }
            };

            let Some(task_registry) = task_registry.upgrade() else {
                tracing::debug!(
                    "Task manager has been dropped, task {:?} no longer monitored",
                    task_variant
                );
                return;
            };

            let mut task_registry = task_registry.write().await;

            if !task_registry.contains_key(&task_variant) {
                tracing::error!(
                    "Invariant violated: Monitored task {:?} not registered in the task registry",
                    task_variant
                );
                return;
            }

            task_registry
                .entry(task_variant)
                .and_modify(|(status, _, _)| {
                    *status = TaskStatus::NotRunning(exit_reason);
                });
        });
    }

    /// Checks if a task is running by checking the task registry
    async fn is_task_running(&self, variant: TaskVariant) -> bool {
        self.task_registry
            .read()
            .await
            .get(&variant)
            .map(|(status, _, _)| status == &TaskStatus::Running)
            .unwrap_or(false)
    }

    /// Gets all tasks that are not running
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

    /// Gets the status of a single task by checking the task registry
    pub async fn get_task_status(&self, variant: TaskVariant) -> Option<TaskStatus> {
        self.task_registry
            .read()
            .await
            .get(&variant)
            .map(|(status, _, _)| status.clone())
    }

    /// Wraps the task in a cancelable loop and spawns it, registers it in the
    /// task registry. If a task with the same TaskVariant is already running,
    /// it will not be started.
    pub async fn ensure_task_looping<S, U: IntoTask<Task = S>>(&self, task: U)
    where
        S: Task + Sized + std::fmt::Debug,
        <S as Task>::Output: Into<bool>,
    {
        self.ensure_monitor_running().await;

        let variant = S::VARIANT;

        // do not start the same task if it is already running
        if self.is_task_running(variant).await {
            tracing::debug!("Task {:?} is already running, skipping", variant);
            return;
        }

        let task = task.into_task();
        let (task, cancel_tx) = task.cancelable_loop();

        let join_handle = task.into_bg();
        let abort_handle = join_handle.abort_handle();

        self.task_registry.write().await.insert(
            variant,
            (TaskStatus::Running, abort_handle, Some(cancel_tx)),
        );

        self.monitor_spawned_task(join_handle, variant);
    }

    async fn ensure_monitor_running(&self) {
        if !self.is_task_running(TaskVariant::TaskStatusMonitor).await {
            let task = TaskStatusMonitorTask::new(self.task_registry.clone())
                .with_delay(TASK_STATUS_MONITOR_POLL_DELAY);

            let variant = TaskVariant::TaskStatusMonitor;
            let (task, cancel_tx) = task.cancelable_loop();
            let bg_task = task.into_bg();
            let abort_handle = bg_task.abort_handle();

            self.task_registry.write().await.insert(
                variant,
                (TaskStatus::Running, abort_handle, Some(cancel_tx)),
            );

            self.monitor_spawned_task(bg_task, variant);
        }
    }

    /// Sends cancel signals to all tasks that have a cancel_tx
    async fn send_cancel_signals(&self) {
        let mut task_registry = self.task_registry.write().await;
        for (_, (_, _, cancel_tx)) in task_registry.iter_mut() {
            let oneshot_tx = cancel_tx.take();
            if let Some(oneshot_tx) = oneshot_tx {
                // send can fail, but if it fails the task is dropped.
                let _ = oneshot_tx.send(());
            }
        }
    }

    /// Abort all tasks by dropping their cancellation senders
    pub fn abort_all(&mut self) {
        tracing::info!("Aborting all tasks");

        // only one thread must have &mut self, so lock should be able to be acquired
        if let Ok(task_registry) = self.task_registry.try_read() {
            for (_, (_, abort_handle, _)) in task_registry.iter() {
                abort_handle.abort();
            }
        }
    }

    /// Graceful shutdown of all tasks
    ///
    /// This function does not have any timeout, please use
    /// `graceful_shutdown_with_timeout` instead for cases where you need a
    /// timeout. The function polls tasks until they are finished with a 100ms
    /// poll interval.
    pub async fn graceful_shutdown(&mut self) {
        tracing::info!("Gracefully shutting down all tasks");

        self.send_cancel_signals().await;

        loop {
            let mut all_finished = true;
            let task_registry = self.task_registry.read().await;

            for (_, (_, abort_handle, _)) in task_registry.iter() {
                if !abort_handle.is_finished() {
                    all_finished = false;
                    break;
                }
            }

            if all_finished {
                break;
            }

            sleep(Duration::from_millis(100)).await;
        }
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

impl Drop for BackgroundTaskManager {
    fn drop(&mut self) {
        tracing::info!("Dropping BackgroundTaskManager, aborting all tasks");

        self.abort_all();
    }
}
