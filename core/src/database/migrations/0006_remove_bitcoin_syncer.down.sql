-- Leave legacy state_manager_status and bitcoin_syncer_event_handlers as-is.
-- Rollback runs the old bitcoin syncer/event consumers again, and replaying
-- already-seen finalized blocks or LCP notifications is safer than deriving
-- legacy cursors from the new finalized-block cursor table.
DROP TABLE IF EXISTS finalized_block_fetcher_progress;
