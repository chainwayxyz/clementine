use crate::task::{Task, TaskVariant};
use clementine_errors::BridgeError;
use clementine_tx_sender::task::TxSenderTaskInternal;
use clementine_tx_sender::{TxSender, TxSenderSigner};
use tonic::async_trait;

#[derive(Debug)]
pub struct TxSenderTask<S>
where
    S: TxSenderSigner + 'static,
{
    inner: TxSenderTaskInternal<S>,
}

impl<S> TxSenderTask<S>
where
    S: TxSenderSigner + 'static,
{
    pub fn new(inner: TxSender<S>) -> Self {
        Self {
            inner: TxSenderTaskInternal::new(inner),
        }
    }
}

#[async_trait]
impl<S> Task for TxSenderTask<S>
where
    S: TxSenderSigner + 'static,
{
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TxSender;

    async fn run_once(&mut self) -> Result<bool, BridgeError> {
        self.inner.run_once().await
    }
}

// Implement IntoTask for TxSender
impl<S> crate::task::IntoTask for TxSender<S>
where
    S: TxSenderSigner + 'static,
{
    type Task = TxSenderTask<S>;
    fn into_task(self) -> Self::Task {
        TxSenderTask::new(self)
    }
}
