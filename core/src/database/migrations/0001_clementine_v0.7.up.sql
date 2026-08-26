CREATE INDEX IF NOT EXISTS bitcoin_syncer_txs_txid_idx ON bitcoin_syncer_txs (txid);
CREATE INDEX IF NOT EXISTS bitcoin_syncer_spent_utxos_txid_vout_idx ON bitcoin_syncer_spent_utxos (txid, vout);
CREATE INDEX IF NOT EXISTS bitcoin_blocks_block_hash_idx ON bitcoin_blocks (block_hash);

ALTER TABLE state_manager_status
ADD COLUMN IF NOT EXISTS last_processed_lcp INT;

-- Seed verifier_lcp_syncer from where LCP actually finished, not from the
-- automation block fetcher. That fetcher only enqueues NewFinalizedBlock and
-- can be far ahead of the state manager; LCP ran when the state manager
-- dequeued. Copying the fetcher cursor would skip the queue gap.
--
-- Sources (MAX of whichever exist):
-- - last event of the canonical block at next_height_to_process - 1 (automation)
-- - verifier_finalized_block_fetcher_no_automation (LCP ran in that fetcher)
--
-- Accepted issue (automation source): next_height_to_process - 1 is a finalized
-- height F, but cursor restore treats that event as a raw-chain tip and
-- resumes at F - finality_depth + 2 instead of F + 1. The LCP syncer therefore
-- replays about finality_depth already-finalized blocks on upgrade. The
-- no_automation source is already correct.
INSERT INTO bitcoin_syncer_event_handlers (consumer_handle, last_processed_event_id)
SELECT 'verifier_lcp_syncer', candidate.last_processed_event_id
FROM (
    SELECT MAX(v) AS last_processed_event_id
    FROM (
        VALUES
            ((
                SELECT bse.id
                FROM bitcoin_syncer_events AS bse
                JOIN bitcoin_syncer AS bs ON bs.id = bse.block_id
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
-- Convert persisted effective_fee_rate from sat/vB (`FeeRate::to_sat_per_vb_ceil`)
-- to sat/kWU (`FeeRate::to_sat_per_kwu`). 1 sat/vB = 250 sat/kWU. Existing
-- non-null rows were written in sat/vB; without this, get_sendable_txs treats
-- already-bumped CPFP txs as underfee and keeps re-selecting them.
UPDATE tx_sender_try_to_send_txs
SET effective_fee_rate = effective_fee_rate * 250
WHERE effective_fee_rate IS NOT NULL;
