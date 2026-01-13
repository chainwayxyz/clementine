use crate::task::{Task, TaskVariant};
use clementine_errors::BridgeError;
use clementine_tx_sender::task::TxSenderTaskInternal;
use clementine_tx_sender::{TxSender, TxSenderSigner, TxSenderTxBuilder};
use tonic::async_trait;

#[derive(Debug)]
pub struct TxSenderTask<S, B>
where
    S: TxSenderSigner + 'static,
    B: TxSenderTxBuilder + 'static,
{
    inner: TxSenderTaskInternal<S, B>,
}

impl<S, B> TxSenderTask<S, B>
where
    S: TxSenderSigner + 'static,
    B: TxSenderTxBuilder + 'static,
{
    pub fn new(inner: TxSender<S, B>) -> Self {
        Self {
            inner: TxSenderTaskInternal::new(inner),
        }
    }
}

#[async_trait]
impl<S, B> Task for TxSenderTask<S, B>
where
    S: TxSenderSigner + 'static,
    B: TxSenderTxBuilder + 'static,
{
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TxSender;

    async fn run_once(&mut self) -> Result<bool, BridgeError> {
        self.inner.run_once().await
    }
}

// Implement IntoTask for TxSender
impl<S, B> crate::task::IntoTask for TxSender<S, B>
where
    S: TxSenderSigner + 'static,
    B: TxSenderTxBuilder + 'static,
{
    type Task = TxSenderTask<S, B>;
    fn into_task(self) -> Self::Task {
        TxSenderTask::new(self)
    }
}
