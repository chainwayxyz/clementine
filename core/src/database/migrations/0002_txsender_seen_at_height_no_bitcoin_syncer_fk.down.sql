-- Rollback: restore legacy tx-sender `seen_block_id` columns and triggers.
-- Note: this re-introduces the tx-sender dependency on bitcoin_syncer tables.

-- 1) Re-add legacy columns (no-ops if they already exist)
ALTER TABLE tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS seen_block_id INT DEFAULT NULL;

ALTER TABLE tx_sender_fee_payer_utxos
ADD COLUMN IF NOT EXISTS seen_block_id INT DEFAULT NULL;

ALTER TABLE tx_sender_cancel_try_to_send_outpoints
ADD COLUMN IF NOT EXISTS seen_block_id INT DEFAULT NULL;

ALTER TABLE tx_sender_cancel_try_to_send_txids
ADD COLUMN IF NOT EXISTS seen_block_id INT DEFAULT NULL;

ALTER TABLE tx_sender_activate_try_to_send_txids
ADD COLUMN IF NOT EXISTS seen_block_id INT DEFAULT NULL;

ALTER TABLE tx_sender_activate_try_to_send_outpoints
ADD COLUMN IF NOT EXISTS seen_block_id INT DEFAULT NULL;

-- 2) Drop the new columns
ALTER TABLE tx_sender_try_to_send_txs
DROP COLUMN IF EXISTS seen_at_height;

ALTER TABLE tx_sender_fee_payer_utxos
DROP COLUMN IF EXISTS seen_at_height;

ALTER TABLE tx_sender_cancel_try_to_send_outpoints
DROP COLUMN IF EXISTS seen_at_height;

ALTER TABLE tx_sender_cancel_try_to_send_txids
DROP COLUMN IF EXISTS seen_at_height;

ALTER TABLE tx_sender_activate_try_to_send_txids
DROP COLUMN IF EXISTS seen_at_height;

ALTER TABLE tx_sender_activate_try_to_send_outpoints
DROP COLUMN IF EXISTS seen_at_height;

-- 3) Restore triggers/functions (matching the legacy schema.sql behavior)
CREATE OR REPLACE FUNCTION update_cancel_txids_seen_block_id() RETURNS TRIGGER AS $$ BEGIN
UPDATE tx_sender_cancel_try_to_send_txids
SET seen_block_id = bs.id
FROM bitcoin_syncer_txs bst
    JOIN bitcoin_syncer bs ON bst.block_id = bs.id
WHERE tx_sender_cancel_try_to_send_txids.cancelled_id = NEW.cancelled_id
    AND tx_sender_cancel_try_to_send_txids.txid = NEW.txid
    AND tx_sender_cancel_try_to_send_txids.seen_block_id IS NULL
    AND bst.txid = NEW.txid
    AND bs.is_canonical = TRUE;
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_cancel_txids_seen_block_id ON tx_sender_cancel_try_to_send_txids;
CREATE TRIGGER trigger_update_cancel_txids_seen_block_id
AFTER
INSERT ON tx_sender_cancel_try_to_send_txids FOR EACH ROW EXECUTE FUNCTION update_cancel_txids_seen_block_id();

CREATE OR REPLACE FUNCTION update_cancel_outpoints_seen_block_id() RETURNS TRIGGER AS $$ BEGIN
UPDATE tx_sender_cancel_try_to_send_outpoints
SET seen_block_id = bs.id
FROM bitcoin_syncer_spent_utxos bsu
    JOIN bitcoin_syncer bs ON bsu.block_id = bs.id
WHERE tx_sender_cancel_try_to_send_outpoints.cancelled_id = NEW.cancelled_id
    AND tx_sender_cancel_try_to_send_outpoints.txid = NEW.txid
    AND tx_sender_cancel_try_to_send_outpoints.vout = NEW.vout
    AND tx_sender_cancel_try_to_send_outpoints.seen_block_id IS NULL
    AND bsu.txid = NEW.txid
    AND bsu.vout = NEW.vout
    AND bs.is_canonical = TRUE;
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_cancel_outpoints_seen_block_id ON tx_sender_cancel_try_to_send_outpoints;
CREATE TRIGGER trigger_update_cancel_outpoints_seen_block_id
AFTER
INSERT ON tx_sender_cancel_try_to_send_outpoints FOR EACH ROW EXECUTE FUNCTION update_cancel_outpoints_seen_block_id();

CREATE OR REPLACE FUNCTION update_activate_txids_seen_block_id() RETURNS TRIGGER AS $$ BEGIN
UPDATE tx_sender_activate_try_to_send_txids
SET seen_block_id = bs.id
FROM bitcoin_syncer_txs bst
    JOIN bitcoin_syncer bs ON bst.block_id = bs.id
WHERE tx_sender_activate_try_to_send_txids.activated_id = NEW.activated_id
    AND tx_sender_activate_try_to_send_txids.txid = NEW.txid
    AND tx_sender_activate_try_to_send_txids.seen_block_id IS NULL
    AND bst.txid = NEW.txid
    AND bs.is_canonical = TRUE;
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_activate_txids_seen_block_id ON tx_sender_activate_try_to_send_txids;
CREATE TRIGGER trigger_update_activate_txids_seen_block_id
AFTER
INSERT ON tx_sender_activate_try_to_send_txids FOR EACH ROW EXECUTE FUNCTION update_activate_txids_seen_block_id();

CREATE OR REPLACE FUNCTION update_activate_outpoints_seen_block_id() RETURNS TRIGGER AS $$ BEGIN
UPDATE tx_sender_activate_try_to_send_outpoints
SET seen_block_id = bs.id
FROM bitcoin_syncer_spent_utxos bsu
    JOIN bitcoin_syncer bs ON bsu.block_id = bs.id
WHERE tx_sender_activate_try_to_send_outpoints.activated_id = NEW.activated_id
    AND tx_sender_activate_try_to_send_outpoints.txid = NEW.txid
    AND tx_sender_activate_try_to_send_outpoints.vout = NEW.vout
    AND tx_sender_activate_try_to_send_outpoints.seen_block_id IS NULL
    AND bsu.txid = NEW.txid
    AND bsu.vout = NEW.vout
    AND bs.is_canonical = TRUE;
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_activate_outpoints_seen_block_id ON tx_sender_activate_try_to_send_outpoints;
CREATE TRIGGER trigger_update_activate_outpoints_seen_block_id
AFTER
INSERT ON tx_sender_activate_try_to_send_outpoints FOR EACH ROW EXECUTE FUNCTION update_activate_outpoints_seen_block_id();

