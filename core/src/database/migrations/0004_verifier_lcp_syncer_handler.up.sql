-- Initialize or bump bitcoin_syncer_event_handlers row for verifier_lcp_syncer.
-- This migration is idempotent and only ever increases last_processed_event_id.
-- It initializes verifier_lcp_syncer's last_processed_event_id based on:
-- - the event id at the canonical block whose height is state_manager_status.next_height_to_process - 1
--   for owner_type = 'verifier' (complex query below),
-- - and verifier_finalized_block_fetcher_no_automation's last_processed_event_id.
-- If verifier_lcp_syncer already has a row, this migration does nothing.
INSERT INTO bitcoin_syncer_event_handlers (consumer_handle, last_processed_event_id)
SELECT
    'verifier_lcp_syncer',
    candidate.last_processed_event_id
FROM (
    SELECT MAX(v) AS last_processed_event_id
    FROM (
        VALUES
            ((
                SELECT bse.id
                FROM bitcoin_syncer_events AS bse
                JOIN bitcoin_syncer AS bs
                    ON bs.id = bse.block_id
                WHERE bs.is_canonical = TRUE
                  AND bs.height = (
                      SELECT next_height_to_process - 1
                      FROM state_manager_status
                      WHERE owner_type = 'verifier'
                  )
                ORDER BY bse.id DESC
                LIMIT 1
            )),
            ((
                SELECT last_processed_event_id
                FROM bitcoin_syncer_event_handlers
                WHERE consumer_handle = 'verifier_finalized_block_fetcher_no_automation'
            ))
    ) AS source_values(v)
    WHERE v IS NOT NULL
) AS candidate
WHERE candidate.last_processed_event_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM bitcoin_syncer_event_handlers
      WHERE consumer_handle = 'verifier_lcp_syncer'
  );