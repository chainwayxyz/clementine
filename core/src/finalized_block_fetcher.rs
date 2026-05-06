use crate::{
    config::protocol::ProtocolParamset,
    database::{Database, DatabaseTransaction, FinalizedBlockProgress},
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

#[derive(Debug, Clone)]
pub struct FinalizedBlockCursor {
    db: Database,
    rpc: ExtendedBitcoinRpc,
    consumer_handle: String,
    paramset: &'static ProtocolParamset,
    next_finalized_height: u32,
    last_processed: Option<(u32, BlockHash)>,
    last_fetched: Option<(u32, BlockHash)>,
    unrecoverable_reorg: Option<String>,
}

impl FinalizedBlockCursor {
    /// Loads persisted progress for a consumer and returns a cursor positioned at
    /// the next finalized block to process.
    ///
    /// If persisted progress is missing a block hash, it is backfilled. If no
    /// progress exists, `initial_last_processed_height` can seed progress from
    /// the state manager's already-processed height.
    pub async fn new(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
        initial_last_processed_height: Option<u32>,
    ) -> Result<Self, BridgeError> {
        let mut progress = normalized_progress(
            paramset,
            db.get_finalized_block_progress(None, &consumer_handle)
                .await?,
        );

        if let Some(db_progress) = &mut progress {
            backfill_missing_progress_hash(&db, &rpc, &consumer_handle, db_progress).await?;
        } else if let Some(height) =
            initial_last_processed_height.filter(|height| *height >= paramset.start_height)
        {
            let block_hash = rpc.get_block_hash(height.into()).await.wrap_err_with(|| {
                format!("Failed to fetch block hash at finalized progress height {height}")
            })?;
            db.upsert_finalized_block_progress(None, &consumer_handle, height, block_hash)
                .await?;
            progress = Some(progress_from_height(height, Some(block_hash)));
        }

        Ok(Self::from_progress(
            db,
            rpc,
            consumer_handle,
            paramset,
            progress,
        ))
    }

    /// Builds an in-memory cursor from a known last processed height without DB
    /// I/O.
    ///
    /// The progress hash is intentionally unknown here; callers should reconcile
    /// the cursor with persisted progress before using it to fetch blocks.
    pub fn from_last_processed_height(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
        last_processed_height: Option<u32>,
    ) -> Self {
        Self::from_progress(
            db,
            rpc,
            consumer_handle,
            paramset,
            last_processed_height.map(|height| progress_from_height(height, None)),
        )
    }

    /// Creates cursor state from an optional progress snapshot.
    fn from_progress(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        consumer_handle: String,
        paramset: &'static ProtocolParamset,
        progress: Option<FinalizedBlockProgress>,
    ) -> Self {
        let progress = normalized_progress(paramset, progress);
        let next_finalized_height = next_height_from_progress(paramset, progress.as_ref());
        let last_processed = last_processed_from_progress(progress);

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
            last_fetched: None,
            unrecoverable_reorg: None,
        }
    }

    /// Aligns persisted cursor progress with the state manager's current height.
    ///
    /// This is used before the cursor starts polling. It seeds missing progress
    /// when the state manager has already processed finalized blocks, backfills
    /// missing hashes, and rejects mismatches between DB progress and state
    /// manager state.
    pub async fn reconcile_progress_with_current_height(
        &mut self,
        current_last_processed_height: Option<u32>,
    ) -> Result<(), BridgeError> {
        let current_last_processed_height =
            current_last_processed_height.filter(|height| *height >= self.paramset.start_height);
        let progress = self
            .db
            .get_finalized_block_progress(None, &self.consumer_handle)
            .await?;
        let progress = normalized_progress(self.paramset, progress);

        match (progress, current_last_processed_height) {
            (None, None) => self.reset_to_progress(None),
            (None, Some(height)) => {
                let progress = self.progress_with_hash(height).await?;
                self.db
                    .upsert_finalized_block_progress(
                        None,
                        &self.consumer_handle,
                        progress.last_processed_height,
                        progress
                            .last_processed_block_hash
                            .expect("progress_with_hash always sets block hash"),
                    )
                    .await?;
                self.reset_to_progress(Some(progress));
            }
            (Some(mut progress), Some(height)) if progress.last_processed_height == height => {
                backfill_missing_progress_hash(
                    &self.db,
                    &self.rpc,
                    &self.consumer_handle,
                    &mut progress,
                )
                .await?;
                self.reset_to_progress(Some(progress));
            }
            (Some(progress), current) => {
                return Err(eyre::eyre!(
                    "Finalized block cursor progress mismatch for consumer {}: state manager last processed height {:?}, database last processed height {}",
                    self.consumer_handle,
                    current,
                    progress.last_processed_height
                )
                .into());
            }
        }

        Ok(())
    }

    /// Reloads cursor progress from the database after a recoverable error.
    ///
    /// Any missing persisted block hash is backfilled before the in-memory cursor
    /// is reset.
    pub async fn recover_from_db(&mut self) -> Result<(), BridgeError> {
        let mut progress = normalized_progress(
            self.paramset,
            self.db
                .get_finalized_block_progress(None, &self.consumer_handle)
                .await?,
        );
        if let Some(progress) = &mut progress {
            backfill_missing_progress_hash(&self.db, &self.rpc, &self.consumer_handle, progress)
                .await?;
        }
        self.reset_to_progress(progress);
        Ok(())
    }

    /// Resets in-memory cursor state from a last processed height without
    /// touching the database.
    pub fn reset_to_last_processed_height(&mut self, last_processed_height: Option<u32>) {
        self.reset_to_progress(
            last_processed_height.map(|height| progress_from_height(height, None)),
        );
    }

    /// Applies a progress snapshot to the in-memory cursor and clears any cached
    /// fetched block.
    fn reset_to_progress(&mut self, progress: Option<FinalizedBlockProgress>) {
        let progress = normalized_progress(self.paramset, progress);
        self.next_finalized_height = next_height_from_progress(self.paramset, progress.as_ref());
        self.last_processed = last_processed_from_progress(progress);
        self.last_fetched = None;
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
        self.last_fetched = Some((block_height, block.block_hash()));

        Ok(Some((block_height, block)))
    }

    /// Persists the processed finalized height and block hash in the supplied
    /// transaction.
    ///
    /// Uses the hash cached by `next_finalized_block` when it matches
    /// `block_height`; otherwise fetches the hash directly.
    pub async fn save_progress(
        &self,
        dbtx: DatabaseTransaction<'_>,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let block_hash = match self.last_fetched {
            Some((height, hash)) if height == block_height => hash,
            _ => self.hash_at_progress_height(block_height).await?,
        };

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
        self.last_fetched = None;
        self.next_finalized_height = block_height.saturating_add(1);
    }

    /// Verifies that the last processed finalized block is still canonical.
    ///
    /// A mismatch is treated as unrecoverable and latched so later polls return
    /// the same error without continuing.
    async fn ensure_latest_processed_block_is_still_canonical(
        &mut self,
    ) -> Result<(), BridgeError> {
        if let Some(error) = &self.unrecoverable_reorg {
            return Err(eyre::eyre!("{error}").into());
        }

        let Some((last_processed_height, last_processed_hash)) = self.last_processed else {
            return Ok(());
        };

        let current_hash = self.hash_at_progress_height(last_processed_height).await?;

        if current_hash != last_processed_hash {
            let error = format!(
                "Finalized block reorg detected for consumer {} at height {}: stored hash {}, current hash {}",
                self.consumer_handle,
                last_processed_height,
                last_processed_hash,
                current_hash
            );
            self.unrecoverable_reorg = Some(error.clone());
            return Err(eyre::eyre!("{error}").into());
        }

        Ok(())
    }

    /// Builds a progress value by fetching the canonical block hash at the given
    /// processed height.
    async fn progress_with_hash(
        &self,
        last_processed_height: u32,
    ) -> Result<FinalizedBlockProgress, BridgeError> {
        Ok(FinalizedBlockProgress {
            last_processed_height,
            last_processed_block_hash: Some(
                self.hash_at_progress_height(last_processed_height).await?,
            ),
        })
    }

    /// Fetches the block hash used for progress persistence and reorg checks.
    async fn hash_at_progress_height(&self, height: u32) -> Result<BlockHash, BridgeError> {
        self.rpc
            .get_block_hash(height.into())
            .await
            .wrap_err_with(|| {
                format!("Failed to fetch block hash at finalized progress height {height}")
            })
            .map_err(Into::into)
    }
}

fn normalized_progress(
    paramset: &ProtocolParamset,
    progress: Option<FinalizedBlockProgress>,
) -> Option<FinalizedBlockProgress> {
    progress.filter(|progress| progress.last_processed_height >= paramset.start_height)
}

fn progress_from_height(
    last_processed_height: u32,
    last_processed_block_hash: Option<BlockHash>,
) -> FinalizedBlockProgress {
    FinalizedBlockProgress {
        last_processed_height,
        last_processed_block_hash,
    }
}

fn last_processed_from_progress(
    progress: Option<FinalizedBlockProgress>,
) -> Option<(u32, BlockHash)> {
    progress.and_then(|progress| {
        progress
            .last_processed_block_hash
            .map(|hash| (progress.last_processed_height, hash))
    })
}

async fn backfill_missing_progress_hash(
    db: &Database,
    rpc: &ExtendedBitcoinRpc,
    consumer_handle: &str,
    progress: &mut FinalizedBlockProgress,
) -> Result<(), BridgeError> {
    if progress.last_processed_block_hash.is_some() {
        return Ok(());
    }

    let block_hash = rpc
        .get_block_hash(progress.last_processed_height.into())
        .await
        .wrap_err_with(|| {
            format!(
                "Failed to fetch block hash at finalized progress height {}",
                progress.last_processed_height
            )
        })?;
    db.upsert_finalized_block_progress(
        None,
        consumer_handle,
        progress.last_processed_height,
        block_hash,
    )
    .await?;
    progress.last_processed_block_hash = Some(block_hash);

    Ok(())
}

fn next_height_from_progress(
    paramset: &ProtocolParamset,
    progress: Option<&FinalizedBlockProgress>,
) -> u32 {
    progress
        .map(|progress| progress.last_processed_height.saturating_add(1))
        .unwrap_or(paramset.start_height)
        .max(paramset.start_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::FinalizedBlockProgress,
        test::common::{
            create_regtest_rpc, create_test_config_with_thread_name, set_test_protocol_paramset,
            WithProcessCleanup,
        },
    };
    use bitcoin::hashes::Hash as _;

    struct CursorTest {
        config: crate::config::BridgeConfig,
        regtest: WithProcessCleanup,
        db: Database,
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

        async fn cursor(
            &self,
            consumer_handle: &str,
            initial_last_processed_height: Option<u32>,
        ) -> FinalizedBlockCursor {
            FinalizedBlockCursor::new(
                self.db.clone(),
                self.regtest.rpc().clone(),
                consumer_handle.to_string(),
                self.config.protocol_paramset(),
                initial_last_processed_height,
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

        async fn block_hash(&self, height: u32) -> BlockHash {
            self.regtest
                .rpc()
                .get_block_hash(height.into())
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
        cursor.save_progress(&mut dbtx, height).await.unwrap();
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
            .cursor("test_no_work", None)
            .await
            .next_finalized_block()
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn cursor_processes_one_block_and_resumes() {
        let test = CursorTest::new(1, 2).await;
        let mut cursor = test.cursor("test_resume", None).await;
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

        let mut resumed_cursor = test.cursor("test_resume", None).await;
        let (height, _) = next_block(&mut resumed_cursor).await;
        assert_eq!(height, 2);
    }

    #[tokio::test]
    async fn cursor_seeds_missing_progress_from_initial_height() {
        let test = CursorTest::new(1, 2).await;
        let initial_height = 5;
        let mut cursor = test
            .cursor("test_initial_progress", Some(initial_height))
            .await;

        assert_eq!(
            test.progress("test_initial_progress").await,
            Some(progress_from_height(
                initial_height,
                Some(test.block_hash(initial_height).await)
            ))
        );

        let (height, _) = next_block(&mut cursor).await;
        assert_eq!(height, initial_height + 1);
    }

    #[tokio::test]
    async fn cursor_does_not_persist_progress_until_saved() {
        let test = CursorTest::new(1, 2).await;
        let mut cursor = test.cursor("test_no_persist_before_save", None).await;
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
        let mut cursor = test.cursor("test_reorg", None).await;
        cursor.next_finalized_height = 2;
        cursor.last_processed = Some((1, BlockHash::all_zeros()));
        assert_reorg_error(&mut cursor).await;
    }

    #[tokio::test]
    async fn cursor_errors_on_persisted_finalized_reorg_mismatch() {
        let test = CursorTest::new(1, 1).await;
        test.save_progress("test_persisted_reorg", 1, BlockHash::all_zeros())
            .await;
        assert_reorg_error(&mut test.cursor("test_persisted_reorg", None).await).await;
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
        assert_reorg_error(
            &mut test
                .cursor("test_persisted_reorg_before_finality", None)
                .await,
        )
        .await;
    }

    #[tokio::test]
    async fn cursor_ignores_pre_start_progress_for_canonicality() {
        let test = CursorTest::new(1_000, 2).await;
        test.save_progress("test_pre_start_progress", 1, BlockHash::all_zeros())
            .await;
        let mut cursor = test.cursor("test_pre_start_progress", None).await;

        assert_eq!(
            cursor.next_finalized_height,
            test.config.protocol_paramset().start_height
        );
        assert_eq!(cursor.last_processed, None);
        assert!(cursor.next_finalized_block().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn cursor_recover_backfills_missing_progress_hash() {
        let test = CursorTest::new(1, 2).await;
        let consumer_handle = "test_recover_missing_hash";
        let mut cursor = test.cursor(consumer_handle, None).await;

        sqlx::query(
            "INSERT INTO finalized_block_fetcher_progress (
                consumer_handle,
                last_processed_height,
                last_processed_block_hash
            ) VALUES ($1, $2, NULL)",
        )
        .bind(consumer_handle)
        .bind(1_i32)
        .execute(&test.db.get_pool())
        .await
        .unwrap();

        cursor.recover_from_db().await.unwrap();

        let expected_hash = test.block_hash(1).await;
        assert_eq!(
            test.progress(consumer_handle).await,
            Some(progress_from_height(1, Some(expected_hash)))
        );
        assert_eq!(cursor.last_processed, Some((1, expected_hash)));
    }
}
