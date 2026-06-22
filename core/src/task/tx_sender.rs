use std::time::Duration;

use crate::task::{BufferedErrors, TaskExt, WithDelay};
use crate::task::{RecoverableTask, Task, TaskVariant};
use clementine_errors::BridgeError;
use clementine_tx_sender::task::TxSenderTaskInternal;
use clementine_tx_sender::TxSender;
use tonic::async_trait;

pub const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(400)
} else {
    Duration::from_secs(30)
};

#[derive(Debug)]
pub struct TxSenderTask {
    inner: TxSenderTaskInternal,
}

impl TxSenderTask {
    pub fn new(inner: TxSender) -> Self {
        Self {
            inner: TxSenderTaskInternal::new(inner),
        }
    }
}

#[async_trait]
impl Task for TxSenderTask {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TxSender;

    async fn run_once(&mut self) -> Result<bool, BridgeError> {
        self.inner.run_once().await
    }
}

#[async_trait]
impl RecoverableTask for TxSenderTask {
    async fn recover_from_error(&mut self, _error: &BridgeError) -> Result<(), BridgeError> {
        // No special recovery needed; retry on next run.
        Ok(())
    }
}

// Implement IntoTask for TxSender
impl crate::task::IntoTask for TxSender {
    type Task = WithDelay<BufferedErrors<TxSenderTask>>;
    fn into_task(self) -> Self::Task {
        TxSenderTask::new(self)
            .into_buffered_errors(10, 1, Duration::from_secs(10))
            .with_delay(POLL_DELAY)
    }
}
