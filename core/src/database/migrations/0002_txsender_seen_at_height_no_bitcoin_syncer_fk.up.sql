-- Decouple tx-sender confirmation tracking from bitcoin_syncer tables.
--
-- Replaces tx-sender `seen_block_id` (bitcoin_syncer FK) with `seen_at_height`
-- (first-observed chain height), and drops the bitcoin_syncer-driven triggers.
--
-- This migration is written to be idempotent because fresh DBs are bootstrapped
-- from schema.sql and then all migrations are applied.
-- 1) Add new columns (no-ops if already present)
ALTER TABLE tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS seen_at_height INT DEFAULT NULL;
ALTER TABLE tx_sender_fee_payer_utxos
ADD COLUMN IF NOT EXISTS seen_at_height INT DEFAULT NULL;
ALTER TABLE tx_sender_cancel_try_to_send_outpoints
ADD COLUMN IF NOT EXISTS seen_at_height INT DEFAULT NULL;
ALTER TABLE tx_sender_cancel_try_to_send_txids
ADD COLUMN IF NOT EXISTS seen_at_height INT DEFAULT NULL;
ALTER TABLE tx_sender_activate_try_to_send_txids
ADD COLUMN IF NOT EXISTS seen_at_height INT DEFAULT NULL;
ALTER TABLE tx_sender_activate_try_to_send_outpoints
ADD COLUMN IF NOT EXISTS seen_at_height INT DEFAULT NULL;
-- 2) Backfill from bitcoin_syncer.height when legacy columns exist
DO $$ BEGIN IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'tx_sender_try_to_send_txs'
        AND column_name = 'seen_block_id'
) THEN EXECUTE $q$
UPDATE tx_sender_try_to_send_txs t
SET seen_at_height = bs.height
FROM bitcoin_syncer bs
WHERE t.seen_at_height IS NULL
    AND t.seen_block_id IS NOT NULL
    AND bs.id = t.seen_block_id $q$;
END IF;
IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'tx_sender_fee_payer_utxos'
        AND column_name = 'seen_block_id'
) THEN EXECUTE $q$
UPDATE tx_sender_fee_payer_utxos f
SET seen_at_height = bs.height
FROM bitcoin_syncer bs
WHERE f.seen_at_height IS NULL
    AND f.seen_block_id IS NOT NULL
    AND bs.id = f.seen_block_id $q$;
END IF;
IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'tx_sender_cancel_try_to_send_outpoints'
        AND column_name = 'seen_block_id'
) THEN EXECUTE $q$
UPDATE tx_sender_cancel_try_to_send_outpoints o
SET seen_at_height = bs.height
FROM bitcoin_syncer bs
WHERE o.seen_at_height IS NULL
    AND o.seen_block_id IS NOT NULL
    AND bs.id = o.seen_block_id $q$;
END IF;
IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'tx_sender_cancel_try_to_send_txids'
        AND column_name = 'seen_block_id'
) THEN EXECUTE $q$
UPDATE tx_sender_cancel_try_to_send_txids t
SET seen_at_height = bs.height
FROM bitcoin_syncer bs
WHERE t.seen_at_height IS NULL
    AND t.seen_block_id IS NOT NULL
    AND bs.id = t.seen_block_id $q$;
END IF;
IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'tx_sender_activate_try_to_send_txids'
        AND column_name = 'seen_block_id'
) THEN EXECUTE $q$
UPDATE tx_sender_activate_try_to_send_txids t
SET seen_at_height = bs.height
FROM bitcoin_syncer bs
WHERE t.seen_at_height IS NULL
    AND t.seen_block_id IS NOT NULL
    AND bs.id = t.seen_block_id $q$;
END IF;
IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'tx_sender_activate_try_to_send_outpoints'
        AND column_name = 'seen_block_id'
) THEN EXECUTE $q$
UPDATE tx_sender_activate_try_to_send_outpoints o
SET seen_at_height = bs.height
FROM bitcoin_syncer bs
WHERE o.seen_at_height IS NULL
    AND o.seen_block_id IS NOT NULL
    AND bs.id = o.seen_block_id $q$;
END IF;
END $$;
-- 3) Drop legacy triggers/functions (no-ops if already absent)
DROP TRIGGER IF EXISTS trigger_update_cancel_txids_seen_block_id ON tx_sender_cancel_try_to_send_txids;
DROP TRIGGER IF EXISTS trigger_update_cancel_outpoints_seen_block_id ON tx_sender_cancel_try_to_send_outpoints;
DROP TRIGGER IF EXISTS trigger_update_activate_txids_seen_block_id ON tx_sender_activate_try_to_send_txids;
DROP TRIGGER IF EXISTS trigger_update_activate_outpoints_seen_block_id ON tx_sender_activate_try_to_send_outpoints;
DROP FUNCTION IF EXISTS update_cancel_txids_seen_block_id();
DROP FUNCTION IF EXISTS update_cancel_outpoints_seen_block_id();
DROP FUNCTION IF EXISTS update_activate_txids_seen_block_id();
DROP FUNCTION IF EXISTS update_activate_outpoints_seen_block_id();
-- 4) Drop legacy columns (no-ops if already absent)
ALTER TABLE tx_sender_try_to_send_txs DROP COLUMN IF EXISTS seen_block_id;
ALTER TABLE tx_sender_fee_payer_utxos DROP COLUMN IF EXISTS seen_block_id;
ALTER TABLE tx_sender_cancel_try_to_send_outpoints DROP COLUMN IF EXISTS seen_block_id;
ALTER TABLE tx_sender_cancel_try_to_send_txids DROP COLUMN IF EXISTS seen_block_id;
ALTER TABLE tx_sender_activate_try_to_send_txids DROP COLUMN IF EXISTS seen_block_id;
ALTER TABLE tx_sender_activate_try_to_send_outpoints DROP COLUMN IF EXISTS seen_block_id;