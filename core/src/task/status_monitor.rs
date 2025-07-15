use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tonic::async_trait;

use crate::errors::BridgeError;

use super::manager::TaskRegistry;
use super::{manager::TaskStatus, Task, TaskVariant};

pub const TASK_STATUS_MONITOR_POLL_DELAY: Duration = Duration::from_secs(300);

/// A task that monitors the status of all tasks in the background task manager.
/// If a task is not running, it will log an error periodically.
#[derive(Debug)]
pub struct TaskStatusMonitorTask {
    task_registry: Arc<RwLock<TaskRegistry>>,
}

impl TaskStatusMonitorTask {
    pub fn new(task_registry: Arc<RwLock<TaskRegistry>>) -> Self {
        Self { task_registry }
    }
}

#[async_trait]
impl Task for TaskStatusMonitorTask {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TaskStatusMonitor;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let task_registry = self.task_registry.read().await;
        for (task_variant, (task_status, _, _)) in task_registry.iter() {
            if let TaskStatus::NotRunning(reason) = task_status {
                tracing::error!("Task {:?} is not running: {}", task_variant, reason);
            }
        }
        Ok(false)
    }
}
