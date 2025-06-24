use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tonic::async_trait;

use crate::{errors::BridgeError, utils::NamedEntity};

use super::{
    manager::{BackgroundTaskManager, TaskStatus},
    Task, TaskVariant,
};

pub const TASK_STATUS_MONITOR_POLL_DELAY: Duration = Duration::from_secs(300);

/// A task that monitors the status of all tasks in the background task manager.
/// If a task is not running, it will log an error periodically.
#[derive(Debug, Clone)]
pub struct TaskStatusMonitorTask<C: NamedEntity + Send + 'static> {
    background_tasks: Arc<Mutex<BackgroundTaskManager<C>>>,
}

impl<C: NamedEntity + Send + 'static> TaskStatusMonitorTask<C> {
    pub fn new(background_tasks: Arc<Mutex<BackgroundTaskManager<C>>>) -> Self {
        Self { background_tasks }
    }
}

#[async_trait]
impl<C: NamedEntity + Send + 'static> Task for TaskStatusMonitorTask<C> {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TaskStatusMonitor;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let mut tasks = self.background_tasks.lock().await;
        for (task_variant, task_status) in tasks.tasks_status.iter() {
            match task_status {
                TaskStatus::NotRunning(reason) => {
                    tracing::error!("Task {:?} is not running: {}", task_variant, reason);
                }
                _ => {}
            }
        }
        Ok(false)
    }
}
