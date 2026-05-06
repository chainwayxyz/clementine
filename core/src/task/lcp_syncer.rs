use std::sync::Arc;

use crate::builder::block_cache::BlockCache;
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::database::Database;
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::finalized_block_fetcher::FinalizedBlockCursor;
use crate::task::{RecoverableTask, Task, TaskVariant};
use crate::verifier::Verifier;
use clementine_errors::BridgeError;
use tonic::async_trait;

#[derive(Debug)]
pub struct LcpSyncerTask<C: CitreaClientT> {
    db: Database,
    cursor: FinalizedBlockCursor,
    verifier: Verifier<C>,
}

impl<C: CitreaClientT> LcpSyncerTask<C> {
    pub async fn new(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
        initial_last_processed_height: Option<u32>,
        verifier: Verifier<C>,
    ) -> Result<Self, BridgeError> {
        let cursor = FinalizedBlockCursor::new(
            db.clone(),
            rpc,
            consumer_handle,
            paramset,
            initial_last_processed_height,
        )
        .await?;

        Ok(Self {
            db,
            cursor,
            verifier,
        })
    }
}

#[async_trait]
impl<C: CitreaClientT> Task for LcpSyncerTask<C> {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::LcpSyncer;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let Some((height, block)) = self.cursor.next_finalized_block().await? else {
            return Ok(false);
        };

        let block_hash = block.block_hash();
        let block_cache = Arc::new(BlockCache::from_block(block, height));
        let mut dbtx = self.db.begin_transaction().await?;

        self.verifier
            .handle_finalized_block(&mut dbtx, height, block_cache, None)
            .await?;
        self.cursor.save_progress(&mut dbtx, height).await?;
        dbtx.commit().await?;
        self.cursor.record_processed(height, block_hash);

        Ok(true)
    }
}

#[async_trait]
impl<C: CitreaClientT> RecoverableTask for LcpSyncerTask<C> {
    async fn recover_from_error(&mut self, _error: &BridgeError) -> Result<(), BridgeError> {
        self.cursor.recover_from_db().await
    }
}
