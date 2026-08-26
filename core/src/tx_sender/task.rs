//! # Transaction Sender Task
//!
//! This module provides the [`Task`] implementation for the [`TxSender`].
//!
//! This task will fetch block events from [`Bitcoin Syncer`](crate::bitcoin_syncer)
//! to keep the consumer cursor and tip height up to date. Confirmations are
//! reconciled against the canonical chain once, immediately before sending.
//! Transactions are picked from the database and sent to the Bitcoin network if
//! a transaction is in queue and not in the [`Bitcoin Syncer`](crate::bitcoin_syncer)
//! database.

use super::TxSender;
use crate::errors::ResultExt;
use crate::task::{IgnoreError, TaskVariant, WithDelay};
use crate::{
    bitcoin_syncer::BitcoinSyncerEvent,
    database::Database,
    errors::BridgeError,
    task::{IntoTask, Task, TaskExt},
};
use std::time::Duration;
use tonic::async_trait;

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(30)
};

#[derive(Debug)]
pub struct TxSenderTask {
    db: Database,
    /// `None` until the first run seeds it from this consumer's persisted syncer cursor. Defaulting
    /// to 0 would make every activation condition look unmet (a timelock is satisfied once
    /// `seen_height + timelock <= tip`), so after a restart no timelock-gated transaction could be
    /// sent until the next block produced a `NewBlock` event.
    current_tip_height: Option<u32>,
    last_processed_tip_height: u32,
    inner: TxSender,
}

impl TxSenderTask {
    /// Returns the current tip height, seeding it from the database on first use.
    async fn tip_height(&mut self) -> Result<u32, BridgeError> {
        match self.current_tip_height {
            Some(height) => Ok(height),
            None => {
                let height = self
                    .db
                    .get_last_processed_event_block_height(None, &self.inner.btc_syncer_consumer_id)
                    .await?
                    .unwrap_or(0);
                self.current_tip_height = Some(height);
                Ok(height)
            }
        }
    }
}

#[async_trait]
impl Task for TxSenderTask {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::TxSender;

    #[tracing::instrument(skip(self), name = "tx_sender_task")]
    async fn run_once(&mut self) -> std::result::Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await.map_to_eyre()?;

        // Events only move the cursor and tip. Reconcile once below, before send.

        if let Some(event) = self
            .db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.inner.btc_syncer_consumer_id)
            .await?
        {
            tracing::info!("Received Bitcoin syncer event: {:?}", event);
            tracing::debug!("TXSENDER: Event: {:?}", event);

            match event {
                BitcoinSyncerEvent::NewBlock(block_id) => {
                    let block_height = self
                        .db
                        .get_block_info_from_id(Some(&mut dbtx), block_id)
                        .await?
                        .ok_or(eyre::eyre!("Block not found in TxSenderTask"))?
                        .1;
                    tracing::info!(
                        height = block_height,
                        block_id = %block_id,
                        "New block"
                    );
                    dbtx.commit().await?;
                    self.current_tip_height = Some(block_height);
                }
                BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                    let height = self
                        .db
                        .get_block_info_from_id(Some(&mut dbtx), block_id)
                        .await?
                        .ok_or(eyre::eyre!("Block not found in TxSenderTask"))?
                        .1;
                    tracing::info!(
                        height = height,
                        block_id = %block_id,
                        "Reorged block"
                    );
                    dbtx.commit().await?;
                }
            }

            // More events may be queued; drain them before sending.
            return Ok(true);
        }

        self.db.sync_transaction_confirmations(&mut dbtx).await?;
        dbtx.commit().await?;

        let current_tip_height = self.tip_height().await?;

        tracing::debug!("TXSENDER: Getting fee rate");
        let fee_rate_result = self.inner.get_fee_rate().await;
        tracing::debug!("TXSENDER: Fee rate result: {:?}", fee_rate_result);
        let fee_rate = fee_rate_result?;

        self.inner
            .try_to_send_unconfirmed_txs(
                fee_rate,
                current_tip_height,
                self.last_processed_tip_height != current_tip_height,
            )
            .await?;
        self.last_processed_tip_height = current_tip_height;

        Ok(false)
    }
}

#[cfg(test)]
impl TxSenderTask {
    pub fn new_for_test(inner: TxSender) -> Self {
        Self {
            db: inner.db.clone(),
            current_tip_height: None,
            last_processed_tip_height: 0,
            inner,
        }
    }
}

impl IntoTask for TxSender {
    type Task = WithDelay<IgnoreError<TxSenderTask>>;

    fn into_task(self) -> Self::Task {
        TxSenderTask {
            db: self.db.clone(),
            current_tip_height: None,
            last_processed_tip_height: 0,
            inner: self,
        }
        .ignore_error()
        .with_delay(POLL_DELAY)
    }
}
