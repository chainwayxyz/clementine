//! # Transaction Sender Task
//!
//! This module provides [`Task`] implementation for [`TxSender`].
//!
//! This task will fetch block events from Bitcoin Syncer and confirms or
//! unconfirms transaction based on the event. Finally, it will try to send
//! candidate transactions.

use super::TxSender;
use crate::errors::ResultExt;
use crate::task::{IgnoreError, WithDelay};
use crate::{
    bitcoin_syncer::BitcoinSyncerEvent,
    database::Database,
    errors::BridgeError,
    task::{IntoTask, Task, TaskExt},
};
use bitcoin::FeeRate;
use std::time::Duration;
use tonic::async_trait;

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(30)
};
#[derive(Debug)]
pub struct TxSenderTask {
    db: Database,
    current_tip_height: u32,
    inner: TxSender,
}

#[async_trait]
impl Task for TxSenderTask {
    type Output = bool;

    async fn run_once(&mut self) -> std::result::Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await.map_to_eyre()?;

        let is_block_update = async {
            let Some(event) = self
                .db
                .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.inner.btc_syncer_consumer_id)
                .await?
            else {
                return Ok(false);
            };

            tracing::info!("TXSENDER: Event: {:?}", event);
            Ok::<_, BridgeError>(match event {
                BitcoinSyncerEvent::NewBlock(block_id) => {
                    self.db.confirm_transactions(&mut dbtx, block_id).await?;
                    self.current_tip_height = self
                        .db
                        .get_block_info_from_id(Some(&mut dbtx), block_id)
                        .await?
                        .ok_or(eyre::eyre!("Block not found in TxSenderTask".to_string(),))?
                        .1;

                    tracing::info!(
                        "TXSENDER: Confirmed transactions for new block with height {} and internal block id {}",
                        self.current_tip_height, block_id
                    );
                    dbtx.commit().await?;
                    true
                }
                BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                    let height = self
                    .db
                    .get_block_info_from_id(Some(&mut dbtx), block_id)
                    .await?
                    .ok_or(eyre::eyre!("Block not found in TxSenderTask".to_string(),))?
                    .1;
                    tracing::info!("TXSENDER: Reorged block with height {} detected, unconfirming transactions for block with internal block id {}", height, block_id);
                    self.db.unconfirm_transactions(&mut dbtx, block_id).await?;
                    dbtx.commit().await?;
                    true
                }
            })
        }
        .await?;

        if is_block_update {
            // Pull in all block updates before trying to send.
            return Ok(true);
        }

        // tracing::info!("TXSENDER: Getting fee rate");
        // let fee_rate_result = self.inner.get_fee_rate().await;
        // tracing::info!("TXSENDER: Fee rate result: {:?}", fee_rate_result);
        // let fee_rate = fee_rate_result?;
        // tracing::info!("TXSENDER: Trying to send unconfirmed txs");
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);

        self.inner
            .try_to_send_unconfirmed_txs(fee_rate, self.current_tip_height)
            .await?;

        Ok(false)
    }
}

impl IntoTask for TxSender {
    type Task = WithDelay<IgnoreError<TxSenderTask>>;

    fn into_task(self) -> Self::Task {
        TxSenderTask {
            db: self.db.clone(),
            current_tip_height: 0,
            inner: self,
        }
        .ignore_error()
        .with_delay(POLL_DELAY)
    }
}
