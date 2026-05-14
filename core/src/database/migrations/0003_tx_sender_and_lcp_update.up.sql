-- Add new fee paying strategy for tx-sender
-- Adding an enum value is idempotent in PG 15+ with IF NOT EXISTS.
-- Keep this as a single statement (no DO $$ blocks) so sqlx migrations can run it reliably.
ALTER TYPE fee_paying_type
ADD VALUE IF NOT EXISTS 'rbf_wtxid_grind';
-- Track mempool presence for txid-based activations used by tx-sender.
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_txids
ADD COLUMN IF NOT EXISTS in_mempool boolean NOT NULL DEFAULT false;
-- Add explicit finality tracking columns to all tx-sender tables.
-- For txid-based tables: finalized when RPC reports confirmations >= finality_depth.
-- For outpoint-based tables: finalized when seen_at_height is set and tip_height - seen_at_height + 1 >= finality_depth.
ALTER TABLE IF EXISTS tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS is_finalized boolean NOT NULL DEFAULT false;
ALTER TABLE IF EXISTS tx_sender_fee_payer_utxos
ADD COLUMN IF NOT EXISTS is_finalized boolean NOT NULL DEFAULT false;
ALTER TABLE IF EXISTS tx_sender_cancel_try_to_send_txids
ADD COLUMN IF NOT EXISTS is_finalized boolean NOT NULL DEFAULT false;
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_txids
ADD COLUMN IF NOT EXISTS is_finalized boolean NOT NULL DEFAULT false;
ALTER TABLE IF EXISTS tx_sender_cancel_try_to_send_outpoints
ADD COLUMN IF NOT EXISTS is_finalized boolean NOT NULL DEFAULT false;
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_outpoints
ADD COLUMN IF NOT EXISTS is_finalized boolean NOT NULL DEFAULT false;
-- Add unique constraint to txid column in tx_sender_try_to_send_txs table
ALTER TABLE tx_sender_try_to_send_txs
ADD CONSTRAINT uq_tx_sender_txid UNIQUE (txid);
-- Add last_processed_lcp column to state_manager_status table
ALTER TABLE state_manager_status
ADD COLUMN IF NOT EXISTS last_processed_lcp INT DEFAULT NULL;
-- Add tx_sender_sync_state table to track the synced height of the Transaction Sender.
CREATE TABLE IF NOT EXISTS tx_sender_sync_state (
    -- Singleton row constraint
    id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    synced_height INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
