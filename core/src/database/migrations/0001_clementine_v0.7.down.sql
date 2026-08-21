DROP INDEX IF EXISTS bitcoin_syncer_txs_txid_idx;
DROP INDEX IF EXISTS bitcoin_syncer_spent_utxos_txid_vout_idx;
DROP INDEX IF EXISTS bitcoin_blocks_block_hash_idx;

-- Keep consumer progress so a downgrade and later upgrade cannot replay old LCP work.
ALTER TABLE state_manager_status DROP COLUMN IF EXISTS last_processed_lcp;
-- Reverse the sat/vB -> sat/kWU conversion of effective_fee_rate.
-- Ceil so a downgrade matches FeeRate::to_sat_per_vb_ceil rather than flooring.
UPDATE tx_sender_try_to_send_txs
SET effective_fee_rate = (effective_fee_rate + 249) / 250
WHERE effective_fee_rate IS NOT NULL;
