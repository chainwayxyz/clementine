-- NOTE: Postgres does not support dropping enum values easily.
-- So enum value is not dropped here.
-- Roll back explicit finality tracking columns from all tx-sender tables.
ALTER TABLE IF EXISTS tx_sender_try_to_send_txs DROP COLUMN IF EXISTS is_finalized;
ALTER TABLE IF EXISTS tx_sender_fee_payer_utxos DROP COLUMN IF EXISTS is_finalized;
ALTER TABLE IF EXISTS tx_sender_cancel_try_to_send_txids DROP COLUMN IF EXISTS is_finalized;
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_txids DROP COLUMN IF EXISTS is_finalized;
ALTER TABLE IF EXISTS tx_sender_cancel_try_to_send_outpoints DROP COLUMN IF EXISTS is_finalized;
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_outpoints DROP COLUMN IF EXISTS is_finalized;
-- Roll back txid activation mempool tracking.
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_txids DROP COLUMN IF EXISTS in_mempool;
-- Drop unique constraint on txid column in tx_sender_try_to_send_txs table
ALTER TABLE tx_sender_try_to_send_txs DROP CONSTRAINT uq_tx_sender_txid;


-- Remove last_processed_lcp column from state_manager_status table
ALTER TABLE state_manager_status DROP COLUMN IF EXISTS last_processed_lcp;