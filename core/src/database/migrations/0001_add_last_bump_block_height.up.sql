-- Add column to track the block height when the last fee bump was done
-- This allows us to bump fees if a transaction hasn't been confirmed for 10 blocks
ALTER TABLE tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS last_bump_block_height INT DEFAULT NULL;

