use std::sync::Arc;

use tonic::async_trait;

use crate::{
    bitcoin_syncer::{BlockHandler, FinalizedBlockFetcherTask},
    builder::block_cache::BlockCache,
    citrea::CitreaClientT,
    config::protocol::ProtocolParamset,
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    task::{RecoverableTask, Task, TaskVariant},
    verifier::Verifier,
};

#[derive(Debug)]
pub struct LcpSyncerTask<H: BlockHandler>(FinalizedBlockFetcherTask<H>);

impl<H: BlockHandler> LcpSyncerTask<H> {
    pub async fn new(
        db: Database,
        consumer_id: String,
        paramset: &'static ProtocolParamset,
        handler: H,
    ) -> Result<Self, BridgeError> {
        // Payouts below genesis_height cannot be proven, and deposits and withdrawals are read
        // by contract index, so heights below it are skipped. Citrea has no light client proof
        // for them after the SP1 migration; see docs/sp1.md#deployment.
        let next_height = db
            .get_next_finalized_block_height_for_consumer(None, &consumer_id, paramset)
            .await?
            .max(paramset.genesis_height);
        Ok(Self(FinalizedBlockFetcherTask::new(
            db,
            consumer_id,
            paramset,
            next_height,
            handler,
        )))
    }
}

#[async_trait]
impl<H: BlockHandler> Task for LcpSyncerTask<H> {
    type Output = bool;
    const VARIANT: TaskVariant = TaskVariant::LcpSyncer;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        self.0.run_once().await
    }
}

#[async_trait]
impl<H: BlockHandler> RecoverableTask for LcpSyncerTask<H> {
    async fn recover_from_error(&mut self, error: &BridgeError) -> Result<(), BridgeError> {
        self.0.recover_from_error(error).await
    }
}

#[async_trait]
impl<C: CitreaClientT> BlockHandler for Verifier<C> {
    async fn handle_new_block(
        &mut self,
        dbtx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        block: bitcoin::Block,
        height: u32,
    ) -> Result<(), BridgeError> {
        self.handle_finalized_block(
            dbtx,
            block_id,
            height,
            Arc::new(BlockCache::from_block(block, height)),
            None,
        )
        .await
    }
}
