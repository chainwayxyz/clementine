CREATE INDEX IF NOT EXISTS bitcoin_syncer_txs_txid_idx ON bitcoin_syncer_txs (txid);

-- Convert persisted effective_fee_rate from sat/vB (`FeeRate::to_sat_per_vb_ceil`)
-- to sat/kWU (`FeeRate::to_sat_per_kwu`). 1 sat/vB = 250 sat/kWU. Existing
-- non-null rows were written in sat/vB; without this, get_sendable_txs treats
-- already-bumped CPFP txs as underfee and keeps re-selecting them.
UPDATE tx_sender_try_to_send_txs
SET effective_fee_rate = effective_fee_rate * 250
WHERE effective_fee_rate IS NOT NULL;
