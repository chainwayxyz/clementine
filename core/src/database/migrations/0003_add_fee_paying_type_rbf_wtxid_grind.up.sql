-- Add new fee paying strategy for tx-sender
DO $$ BEGIN -- Adding an enum value is idempotent in PG 15+ with IF NOT EXISTS.
-- (We still wrap in DO $$ for compatibility with older scripts.)
ALTER TYPE fee_paying_type
ADD VALUE IF NOT EXISTS 'rbf_wtxid_grind';
END $$;
-- Track mempool presence for txid-based activations used by tx-sender.
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_txids
ADD COLUMN IF NOT EXISTS in_mempool boolean NOT NULL DEFAULT false;