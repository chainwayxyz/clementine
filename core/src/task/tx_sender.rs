use crate::task::{Task, TaskVariant};
use clementine_errors::BridgeError;
use clementine_tx_sender::task::TxSenderTaskInternal;
use clementine_tx_sender::TxSender;
use tonic::async_trait;

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

// Implement IntoTask for TxSender
impl crate::task::IntoTask for TxSender {
    type Task = TxSenderTask;
    fn into_task(self) -> Self::Task {
        TxSenderTask::new(self)
    }
}
