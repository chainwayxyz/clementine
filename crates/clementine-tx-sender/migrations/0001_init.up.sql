-- TxSender standalone schema (owned by clementine-tx-sender).
--
-- This migration is intended for standalone txsender deployments, and is written
-- to be idempotent (CREATE IF NOT EXISTS) so repeated startups are safe.
-- fee_paying_type enum used by txsender tables
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'fee_paying_type'
) THEN CREATE TYPE fee_paying_type AS ENUM ('cpfp', 'rbf', 'rbf_wtxid_grind', 'nofunding');
END IF;
END $$;
-- Transactions that are needed to be fee bumped
CREATE TABLE IF NOT EXISTS tx_sender_try_to_send_txs (
    id SERIAL PRIMARY KEY,
    raw_tx BYTEA NOT NULL,
    tx_metadata TEXT,
    fee_paying_type fee_paying_type NOT NULL,
    effective_fee_rate BIGINT,
    txid BYTEA,
    -- first observed chain height when tx was seen confirmed (used for finality tracking)
    seen_at_height INT,
    last_bump_block_height INT DEFAULT NULL,
    latest_active_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    rbf_signing_info TEXT
);
CREATE TABLE IF NOT EXISTS tx_sender_rbf_txids (
    insertion_order SERIAL NOT NULL,
    id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, txid)
);
CREATE TABLE IF NOT EXISTS tx_sender_fee_payer_utxos (
    id SERIAL PRIMARY KEY,
    -- null for first created tx, then the id of first created tx for all replacements
    replacement_of_id INT REFERENCES tx_sender_fee_payer_utxos(id),
    bumped_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    fee_payer_txid BYTEA NOT NULL,
    vout INT NOT NULL,
    amount BIGINT NOT NULL,
    -- first observed chain height when fee payer tx was seen confirmed (used for finality tracking)
    seen_at_height INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    -- if set to false, all replacements of this fee payer utxo are evicted
    is_evicted BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS tx_sender_cancel_try_to_send_outpoints (
    cancelled_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    vout INT NOT NULL,
    -- first observed chain height when this outpoint was seen spent (used for finality tracking)
    seen_at_height INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cancelled_id, txid, vout)
);
CREATE TABLE IF NOT EXISTS tx_sender_cancel_try_to_send_txids (
    cancelled_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    -- first observed chain height when this txid was seen confirmed (used for finality tracking)
    seen_at_height INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cancelled_id, txid)
);
CREATE TABLE IF NOT EXISTS tx_sender_activate_try_to_send_txids (
    activated_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    timelock BIGINT NOT NULL,
    -- first observed chain height when this txid was seen confirmed (used for finality tracking)
    seen_at_height INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (activated_id, txid)
);
CREATE TABLE IF NOT EXISTS tx_sender_activate_try_to_send_outpoints (
    activated_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    vout INT NOT NULL,
    timelock BIGINT NOT NULL,
    -- first observed chain height when this outpoint was seen spent (used for finality tracking)
    seen_at_height INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (activated_id, txid, vout)
);
-- Debug-only tables (used by txsender for diagnostics)
CREATE TABLE IF NOT EXISTS tx_sender_debug_submission_errors (
    id SERIAL PRIMARY KEY,
    tx_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    error_message TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tx_sender_debug_sending_state (
    tx_id INT PRIMARY KEY REFERENCES tx_sender_try_to_send_txs(id),
    state TEXT NOT NULL,
    last_update TIMESTAMP NOT NULL DEFAULT NOW(),
    activated_timestamp TIMESTAMP
);
CREATE INDEX IF NOT EXISTS tx_sender_debug_submission_errors_tx_id_idx ON tx_sender_debug_submission_errors(tx_id);
-- Citrea raw transaction queue for DA payloads.
--
-- Each logical request is grouped by `insertion_id`. For non-chunked payloads
-- there is a single row. For chunked payloads, multiple chunk rows plus a
-- single aggregate row share the same `insertion_id`.
--
-- `body` is globally unique (when non-NULL) to avoid queuing duplicate blobs.
CREATE SEQUENCE IF NOT EXISTS tx_sender_citrea_raw_tx_insertion_id_seq;
CREATE TABLE IF NOT EXISTS tx_sender_citrea_raw_tx_queue (
    id BIGSERIAL PRIMARY KEY,
    -- Group identifier shared across all rows belonging to the same RawTxData
    -- request (chunks and aggregate).
    insertion_id BIGINT NOT NULL DEFAULT nextval('tx_sender_citrea_raw_tx_insertion_id_seq'),
    -- Numeric transaction kind as defined in `citrea::TransactionKind` (u16).
    transaction_kind SMALLINT NOT NULL,
    -- Raw body bytes. Non-NULL for all non-aggregate rows; NULL for the
    -- aggregate placeholder row.
    body BYTEA,
    -- Optional commit outpoint once known (format: "txid:vout").
    commit_outpoint TEXT,
    -- Optional link to a tx_sender_try_to_send_txs row once it exists.
    try_to_send_id INT REFERENCES tx_sender_try_to_send_txs(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (body)
);
CREATE INDEX IF NOT EXISTS tx_sender_citrea_raw_tx_queue_insertion_id_idx ON tx_sender_citrea_raw_tx_queue(insertion_id);
CREATE INDEX IF NOT EXISTS tx_sender_citrea_raw_tx_queue_try_to_send_id_idx ON tx_sender_citrea_raw_tx_queue(try_to_send_id);