use std::sync::Arc;

use crate::bitcoin_syncer::{BlockHandler, FinalizedBlockFetcherTask};
use crate::citrea::CitreaClientT;
use crate::config::protocol::ProtocolParamset;
use crate::database::{Database, DatabaseTransaction};
use crate::states::block_cache::BlockCache;
use crate::task::{RecoverableTask, Task, TaskVariant};
use crate::verifier::Verifier;
use clementine_errors::BridgeError;
use tonic::async_trait;

#[derive(Debug)]
pub struct LcpSyncerTask<H: BlockHandler>(FinalizedBlockFetcherTask<H>);

impl<H: BlockHandler> LcpSyncerTask<H> {
    pub async fn new(
        db: Database,
        btc_syncer_consumer_id: String,
        paramset: &'static ProtocolParamset,
        handler: H,
    ) -> Result<Self, BridgeError> {
        let next_height = db
            .get_next_finalized_block_height_for_consumer(None, &btc_syncer_consumer_id, paramset)
            .await?;

        Ok(Self(FinalizedBlockFetcherTask::new(
            db,
            btc_syncer_consumer_id,
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

#[async_trait::async_trait]
impl<C> crate::bitcoin_syncer::BlockHandler for Verifier<C>
where
    C: CitreaClientT,
{
    async fn handle_new_block(
        &mut self,
        dbtx: DatabaseTransaction<'_>,
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
