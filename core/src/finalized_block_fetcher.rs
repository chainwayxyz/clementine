use crate::{
    config::protocol::ProtocolParamset,
    database::{Database, DatabaseTransaction},
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
};
use bitcoin::{Block, BlockHash};
use bitcoincore_rpc::RpcApi;
use clementine_errors::BridgeError;
use eyre::Context as _;
use std::time::Duration;

pub const FINALIZED_BLOCK_CURSOR_POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(250)
} else {
    Duration::from_secs(30)
};

/// Stateful finalized-block reader for one logical consumer.
///
/// The cursor owns progress persistence and hash checks so callers only need to
/// process a returned block, save progress in their transaction, and then record
/// the committed height in memory.
#[derive(Debug, Clone)]
pub struct FinalizedBlockCursor {
    db: Database,
    rpc: ExtendedBitcoinRpc,
    consumer_handle: String,
    paramset: &'static ProtocolParamset,
    next_finalized_height: u32,
    last_processed: Option<(u32, BlockHash)>,
}

impl FinalizedBlockCursor {
    /// Loads persisted progress for a consumer and returns a cursor positioned at
    /// the next finalized block to process.
    pub async fn new(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
    ) -> Result<Self, BridgeError> {
        let progress = db
            .get_finalized_block_progress(None, &consumer_handle)
            .await?;

        let next_finalized_height = next_height_after_processed(
            paramset,
            progress.as_ref().map(|p| p.last_processed_height),
        );
        let last_processed =
            progress.map(|p| (p.last_processed_height, p.last_processed_block_hash));

        Ok(Self::from_parts(
            db,
            rpc,
            consumer_handle,
            paramset,
            next_finalized_height,
            last_processed,
        ))
    }

    /// Builds a cursor from an already-known last processed height without DB
    /// I/O.
    ///
    /// This constructor is intentionally synchronous. The first async poll will
    /// load the corresponding persisted progress before checking the stored hash.
    pub fn from_last_processed_height(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
        last_processed_height: Option<u32>,
    ) -> Self {
        Self::from_parts(
            db,
            rpc,
            consumer_handle,
            paramset,
            next_height_after_processed(paramset, last_processed_height),
            None,
        )
    }

    /// Creates the cursor after callers have resolved the next height and any
    /// available hash-backed progress.
    fn from_parts(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
        next_finalized_height: u32,
        last_processed: Option<(u32, BlockHash)>,
    ) -> Self {
        tracing::debug!(
            consumer_handle,
            next_finalized_height,
            "Creating finalized block cursor"
        );

        Self {
            db,
            rpc,
            consumer_handle,
            paramset,
            next_finalized_height,
            last_processed,
        }
    }

    /// Fetches the next finalized block, if finality depth has been reached.
    ///
    /// The cursor does not advance here. Call `save_progress` and
    /// `record_processed` after the block has been successfully handled and
    /// committed.
    pub async fn next_finalized_block(&mut self) -> Result<Option<(u32, Block)>, BridgeError> {
        self.ensure_latest_processed_block_is_still_canonical()
            .await?;

        let current_tip_height = self.rpc.get_current_chain_height().await?;
        if !self
            .paramset
            .is_block_finalized(self.next_finalized_height, current_tip_height)
        {
            return Ok(None);
        }

        let block_height = self.next_finalized_height;
        let block = self
            .rpc
            .get_block_by_height(block_height.into())
            .await
            .wrap_err_with(|| {
                format!("Failed to fetch finalized block at height {block_height}")
            })?;

        Ok(Some((block_height, block)))
    }

    /// Persists the processed finalized height and block hash in the supplied
    /// transaction.
    pub async fn save_progress(
        &self,
        dbtx: DatabaseTransaction<'_>,
        block_height: u32,
        block_hash: BlockHash,
    ) -> Result<(), BridgeError> {
        self.db
            .upsert_finalized_block_progress(
                Some(dbtx),
                &self.consumer_handle,
                block_height,
                block_hash,
            )
            .await
    }

    /// Advances the in-memory cursor after the caller has committed block
    /// processing and progress persistence.
    pub fn record_processed(&mut self, block_height: u32, block_hash: BlockHash) {
        self.last_processed = Some((block_height, block_hash));
        self.next_finalized_height = block_height.saturating_add(1);
    }

    /// Verifies that the latest processed finalized block is still canonical.
    ///
    /// Cursors created without DB I/O hydrate progress here before polling.
    /// A hash mismatch is treated as unrecoverable.
    async fn ensure_latest_processed_block_is_still_canonical(
        &mut self,
    ) -> Result<(), BridgeError> {
        if self.last_processed.is_none() {
            let Some(progress) = self
                .db
                .get_finalized_block_progress(None, &self.consumer_handle)
                .await?
            else {
                if self.next_finalized_height == self.paramset.start_height {
                    return Ok(());
                }
                return Err(eyre::eyre!(
                    "Missing finalized block cursor progress for consumer {}",
                    self.consumer_handle
                )
                .into());
            };

            let progress_next =
                next_height_after_processed(self.paramset, Some(progress.last_processed_height));
            if progress_next != self.next_finalized_height {
                return Err(eyre::eyre!(
                    "Finalized block cursor progress mismatch for consumer {}: cursor next height {}, persisted next height {}",
                    self.consumer_handle,
                    self.next_finalized_height,
                    progress_next
                )
                .into());
            }

            self.last_processed = Some((
                progress.last_processed_height,
                progress.last_processed_block_hash,
            ));
        }

        let (last_processed_height, last_processed_hash) =
            self.last_processed.expect("checked above");
        let current_hash = progress_block_hash(&self.rpc, last_processed_height).await?;

        if current_hash != last_processed_hash {
            let error = format!(
                "Finalized block reorg detected for consumer {} at height {}: stored hash {}, current hash {}",
                self.consumer_handle,
                last_processed_height,
                last_processed_hash,
                current_hash
            );
            return Err(eyre::eyre!("{error}").into());
        }

        Ok(())
    }
}

/// Fetches the canonical block hash used for progress persistence and reorg
/// checks.
async fn progress_block_hash(
    rpc: &ExtendedBitcoinRpc,
    height: u32,
) -> Result<BlockHash, BridgeError> {
    rpc.get_block_hash(height.into())
        .await
        .wrap_err_with(|| {
            format!("Failed to fetch block hash at finalized progress height {height}")
        })
        .map_err(Into::into)
}

/// Returns the first height that still needs to be processed, clamped to the
/// configured protocol start height.
fn next_height_after_processed(
    paramset: &ProtocolParamset,
    last_processed_height: Option<u32>,
) -> u32 {
    last_processed_height
        .filter(|height| *height >= paramset.start_height)
        .map(|height| height.saturating_add(1))
        .unwrap_or(paramset.start_height)
        .max(paramset.start_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::FinalizedBlockProgress,
        test::common::{
            create_regtest_rpc, create_test_config_with_thread_name, WithProcessCleanup,
        },
    };
    use bitcoin::hashes::Hash as _;

    struct CursorTest {
        config: crate::config::BridgeConfig,
        regtest: WithProcessCleanup,
        db: Database,
    }

    fn set_test_protocol_paramset(
        config: &mut crate::config::BridgeConfig,
        start_height: u32,
        finality_depth: u32,
    ) {
        let mut paramset = config.protocol_paramset().clone();
        paramset.start_height = start_height;
        paramset.finality_depth = finality_depth;
        config.protocol_paramset = Box::leak(Box::new(paramset));
    }

    impl CursorTest {
        async fn new(start_height: u32, finality_depth: u32) -> Self {
            let mut config = create_test_config_with_thread_name().await;
            set_test_protocol_paramset(&mut config, start_height, finality_depth);
            let regtest = create_regtest_rpc(&mut config).await;
            let db = Database::new(&config).await.unwrap();
            Self {
                config,
                regtest,
                db,
            }
        }

        async fn cursor(&self, consumer_handle: &str) -> FinalizedBlockCursor {
            FinalizedBlockCursor::new(
                self.db.clone(),
                self.regtest.rpc().clone(),
                consumer_handle.to_string(),
                self.config.protocol_paramset(),
            )
            .await
            .unwrap()
        }

        async fn progress(&self, consumer_handle: &str) -> Option<FinalizedBlockProgress> {
            self.db
                .get_finalized_block_progress(None, consumer_handle)
                .await
                .unwrap()
        }

        async fn save_progress(&self, consumer_handle: &str, height: u32, block_hash: BlockHash) {
            self.db
                .upsert_finalized_block_progress(None, consumer_handle, height, block_hash)
                .await
                .unwrap();
        }
    }

    async fn next_block(cursor: &mut FinalizedBlockCursor) -> (u32, Block) {
        cursor.next_finalized_block().await.unwrap().unwrap()
    }

    async fn save_processed(
        db: &Database,
        cursor: &mut FinalizedBlockCursor,
        height: u32,
        block_hash: BlockHash,
    ) {
        let mut dbtx = db.begin_transaction().await.unwrap();
        cursor
            .save_progress(&mut dbtx, height, block_hash)
            .await
            .unwrap();
        dbtx.commit().await.unwrap();
        cursor.record_processed(height, block_hash);
    }

    async fn assert_reorg_error(cursor: &mut FinalizedBlockCursor) {
        let err = cursor.next_finalized_block().await.unwrap_err();
        assert!(
            format!("{err:?}").contains("Finalized block reorg detected"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn cursor_no_work_before_finality() {
        let test = CursorTest::new(1_000, 2).await;
        assert!(test
            .cursor("test_no_work")
            .await
            .next_finalized_block()
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cursor_processes_one_block_and_resumes() {
        let test = CursorTest::new(1, 2).await;
        let mut cursor = test.cursor("test_resume").await;
        let (height, block) = next_block(&mut cursor).await;

        assert_eq!(height, 1);
        save_processed(&test.db, &mut cursor, height, block.block_hash()).await;
        assert_eq!(
            test.progress("test_resume")
                .await
                .unwrap()
                .last_processed_height,
            1
        );

        let mut resumed_cursor = test.cursor("test_resume").await;
        let (height, _) = next_block(&mut resumed_cursor).await;
        assert_eq!(height, 2);
    }

    #[tokio::test]
    async fn cursor_does_not_persist_progress_until_saved() {
        let test = CursorTest::new(1, 2).await;
        let mut cursor = test.cursor("test_no_persist_before_save").await;
        let (height, block) = next_block(&mut cursor).await;

        assert!(test.progress("test_no_persist_before_save").await.is_none());
        save_processed(&test.db, &mut cursor, height, block.block_hash()).await;

        assert_eq!(
            test.progress("test_no_persist_before_save")
                .await
                .unwrap()
                .last_processed_height,
            height
        );
    }

    #[tokio::test]
    async fn cursor_errors_on_in_memory_finalized_reorg_mismatch() {
        let test = CursorTest::new(1, 1).await;
        let mut cursor = test.cursor("test_reorg").await;
        cursor.next_finalized_height = 2;
        cursor.last_processed = Some((1, BlockHash::all_zeros()));
        assert_reorg_error(&mut cursor).await;
    }

    #[tokio::test]
    async fn cursor_errors_on_persisted_finalized_reorg_mismatch() {
        let test = CursorTest::new(1, 1).await;
        test.save_progress("test_persisted_reorg", 1, BlockHash::all_zeros())
            .await;
        assert_reorg_error(&mut test.cursor("test_persisted_reorg").await).await;
    }

    #[tokio::test]
    async fn cursor_from_last_processed_height_checks_persisted_hash() {
        let test = CursorTest::new(1, 1).await;
        let consumer_handle = "test_sync_cursor_reorg";
        test.save_progress(consumer_handle, 1, BlockHash::all_zeros())
            .await;

        let mut cursor = FinalizedBlockCursor::from_last_processed_height(
            test.db.clone(),
            test.regtest.rpc().clone(),
            consumer_handle.to_string(),
            test.config.protocol_paramset(),
            Some(1),
        );

        assert_reorg_error(&mut cursor).await;
    }

    #[tokio::test]
    async fn cursor_checks_persisted_hash_before_finality_gate() {
        let test = CursorTest::new(1, 10_000).await;
        test.save_progress(
            "test_persisted_reorg_before_finality",
            1,
            BlockHash::all_zeros(),
        )
        .await;
        assert_reorg_error(&mut test.cursor("test_persisted_reorg_before_finality").await).await;
    }
}
