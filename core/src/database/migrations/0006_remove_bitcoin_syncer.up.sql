CREATE TABLE IF NOT EXISTS finalized_block_fetcher_progress (
    consumer_handle text primary key,
    last_processed_height int not null,
    last_processed_block_hash text not null,
    created_at timestamp not null default now(),
    updated_at timestamp not null default now()
);

INSERT INTO finalized_block_fetcher_progress (
    consumer_handle,
    last_processed_height,
    last_processed_block_hash
)
SELECT
    state_manager_progress.consumer_handle,
    state_manager_status.next_height_to_process - 1,
    bitcoin_syncer.blockhash
FROM (
    VALUES
        ('verifier', 'verifier_state_manager'),
        ('operator', 'operator_state_manager')
) AS state_manager_progress(owner_type, consumer_handle)
JOIN state_manager_status
    ON state_manager_status.owner_type = state_manager_progress.owner_type
JOIN bitcoin_syncer
    ON bitcoin_syncer.height = state_manager_status.next_height_to_process - 1
   AND bitcoin_syncer.is_canonical = TRUE
WHERE state_manager_status.owner_type IN ('verifier', 'operator')
  AND state_manager_status.next_height_to_process > 0
ON CONFLICT (consumer_handle) DO NOTHING;

WITH legacy_lcp_progress AS (
    -- The legacy handler stores a bitcoin syncer event cursor, not finalized LCP
    -- progress. Rewind by 100, the maximum finality depth, because replaying
    -- already-processed LCP heights is idempotent. If the rewound height is
    -- before the stored bitcoin syncer range, the join below inserts no row
    -- and the new syncer replays from start_height.
    SELECT bitcoin_syncer.height - 100 AS last_processed_height
    FROM bitcoin_syncer_event_handlers AS handler
    JOIN bitcoin_syncer_events
        ON bitcoin_syncer_events.id = handler.last_processed_event_id
    JOIN bitcoin_syncer
        ON bitcoin_syncer.id = bitcoin_syncer_events.block_id
    WHERE handler.consumer_handle = 'verifier_lcp_syncer'
      AND bitcoin_syncer.height >= 100
)
INSERT INTO finalized_block_fetcher_progress (
    consumer_handle,
    last_processed_height,
    last_processed_block_hash
)
SELECT
    'verifier_lcp_syncer',
    progress_block.height,
    progress_block.blockhash
FROM legacy_lcp_progress
JOIN bitcoin_syncer AS progress_block
    ON progress_block.height = legacy_lcp_progress.last_processed_height
   AND progress_block.is_canonical = TRUE
ON CONFLICT (consumer_handle) DO NOTHING;

-- state_manager_status is kept for rollback compatibility.
