-- NOTE: Postgres does not support dropping enum values easily.
-- So enum value is not dropped here.
-- Roll back txid activation mempool tracking.
ALTER TABLE IF EXISTS tx_sender_activate_try_to_send_txids DROP COLUMN IF EXISTS in_mempool;