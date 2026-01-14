use crate::TxSender;
use clementine_errors::BridgeError;
use std::time::Duration;

pub const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(500)
} else {
    Duration::from_secs(60)
};

#[derive(Debug)]
pub struct TxSenderTaskInternal {
    pub current_tip_height: u32,
    pub last_processed_tip_height: u32,
    pub inner: TxSender,
}

impl TxSenderTaskInternal {
    pub fn new(inner: TxSender) -> Self {
        Self {
            current_tip_height: 0,
            last_processed_tip_height: 0,
            inner,
        }
    }

    #[tracing::instrument(skip(self), name = "tx_sender_task")]
    pub async fn run_once(&mut self) -> Result<bool, BridgeError> {
        // Get current tip height from Bitcoin RPC, then sync confirmations/spent tracking.
        self.current_tip_height = self
            .inner
            .rpc
            .get_current_chain_height()
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;
        // No need for db transaction as it doesn't matter if it fails midway, we resync from rpc continuously
        self.inner
            .sync_transaction_confirmations_via_rpc(None, self.current_tip_height)
            .await?;

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
