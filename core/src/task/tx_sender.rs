use crate::task::{Task, TaskVariant};
use clementine_errors::BridgeError;
use clementine_tx_sender::task::TxSenderTaskInternal;
use clementine_tx_sender::{TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder};
use tonic::async_trait;

#[derive(Debug)]
pub struct TxSenderTask<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + Clone + 'static,
    B: TxSenderTxBuilder + 'static,
{
    inner: TxSenderTaskInternal<S, D, B>,
}

impl<S, D, B> TxSenderTask<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + Clone + 'static,
    B: TxSenderTxBuilder + 'static,
{
    pub fn new(inner: TxSender<S, D, B>) -> Self {
        Self {
            inner: TxSenderTaskInternal::new(inner),
        }
    }
}

#[async_trait]
impl<S, D, B> Task for TxSenderTask<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + Clone + 'static,
    B: TxSenderTxBuilder + 'static,
{
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TxSender;

    async fn run_once(&mut self) -> Result<bool, BridgeError> {
        self.inner.run_once().await
    }
}

// Implement IntoTask for TxSender
impl<S, D, B> crate::task::IntoTask for TxSender<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + Clone + 'static,
    B: TxSenderTxBuilder + 'static,
{
    type Task = TxSenderTask<S, D, B>;
    fn into_task(self) -> Self::Task {
        TxSenderTask::new(self)
    }
}
