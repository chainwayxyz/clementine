-- Adds sent_block_id column to tx_sender_try_to_send_txs table
ALTER TABLE tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS sent_block_id INT;
-- Add foreign key constraint separately
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
    WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_name = 'tx_sender_try_to_send_txs'
        AND kcu.column_name = 'sent_block_id'
) THEN
ALTER TABLE tx_sender_try_to_send_txs
ADD CONSTRAINT fk_sent_block FOREIGN KEY (sent_block_id) REFERENCES bitcoin_syncer(id);
END IF;
END $$;