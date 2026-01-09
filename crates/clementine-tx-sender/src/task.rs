use crate::{TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder};
use clementine_errors::BridgeError;
use std::time::Duration;

pub const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(60)
};

#[derive(Debug)]
pub struct TxSenderTaskInternal<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + Clone + 'static,
    B: TxSenderTxBuilder + 'static,
{
    pub current_tip_height: u32,
    pub last_processed_tip_height: u32,
    pub inner: TxSender<S, D, B>,
}

impl<S, D, B> TxSenderTaskInternal<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + Clone + 'static,
    B: TxSenderTxBuilder + 'static,
{
    pub fn new(inner: TxSender<S, D, B>) -> Self {
        Self {
            current_tip_height: 0,
            last_processed_tip_height: 0,
            inner,
        }
    }

    #[tracing::instrument(skip(self), name = "tx_sender_task")]
    pub async fn run_once(&mut self) -> Result<bool, BridgeError> {
        let mut dbtx = self.inner.db.begin_transaction().await?;

        // Sync transaction confirmations based on canonical block status
        self.inner
            .db
            .sync_transaction_confirmations(Some(&mut dbtx))
            .await?;

        // Get current tip height
        self.current_tip_height = self
            .inner
            .db
            .get_max_height(Some(&mut dbtx))
            .await?
            .unwrap_or(0);

        self.inner.db.commit_transaction(dbtx).await?;

        tracing::debug!("TXSENDER: Getting fee rate");
        let fee_rate_result = self.inner.get_fee_rate().await;
        tracing::debug!("TXSENDER: Fee rate result: {:?}", fee_rate_result);
        let fee_rate = fee_rate_result?;

        self.inner
            .try_to_send_unconfirmed_txs(
                fee_rate,
                self.current_tip_height,
                self.last_processed_tip_height != self.current_tip_height,
            )
            .await?;
        self.last_processed_tip_height = self.current_tip_height;

        Ok(false)
    }
}
