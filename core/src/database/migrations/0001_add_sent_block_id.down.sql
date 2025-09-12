ALTER TABLE tx_sender_try_to_send_txs DROP CONSTRAINT IF EXISTS fk_sent_block;
ALTER TABLE tx_sender_try_to_send_txs DROP COLUMN IF EXISTS sent_block_id;