use crate::{TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder};
use clementine_errors::BridgeError;
use clementine_primitives::BitcoinSyncerEvent;
use std::time::Duration;

pub const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(30)
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

        let is_block_update = match self
            .inner
            .db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.inner.btc_syncer_consumer_id)
            .await?
        {
            Some(event) => {
                tracing::info!("Received Bitcoin syncer event: {:?}", event);

                tracing::debug!("TXSENDER: Event: {:?}", event);
                match event {
                    BitcoinSyncerEvent::NewBlock(block_id) => {
                        let block_height = self
                            .inner
                            .db
                            .get_block_info_from_id(Some(&mut dbtx), block_id)
                            .await?
                            .ok_or_else(|| {
                                BridgeError::Eyre(eyre::eyre!("Block not found in TxSenderTask"))
                            })?
                            .1;
                        tracing::info!(
                            height = self.current_tip_height,
                            block_id = %block_id,
                            "Block mined, confirming transactions..."
                        );

                        self.inner
                            .db
                            .confirm_transactions(&mut dbtx, block_id)
                            .await?;

                        self.inner.db.commit_transaction(dbtx).await?;
                        // update after db commit
                        self.current_tip_height = block_height;
                        true
                    }
                    BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                        let height = self
                            .inner
                            .db
                            .get_block_info_from_id(Some(&mut dbtx), block_id)
                            .await?
                            .ok_or_else(|| {
                                BridgeError::Eyre(eyre::eyre!("Block not found in TxSenderTask"))
                            })?
                            .1;
                        tracing::info!(
                            height = height,
                            block_id = %block_id,
                            "Reorged happened, unconfirming transactions..."
                        );

                        self.inner
                            .db
                            .unconfirm_transactions(&mut dbtx, block_id)
                            .await?;

                        self.inner.db.commit_transaction(dbtx).await?;
                        true
                    }
                }
            }
            None => false,
        };

        // If there is a block update, it is possible that there are more.
        // Before sending, fetch all events and process them without waiting.
        if is_block_update {
            return Ok(true);
        }

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
