-- Recreate legacy tx_sender cancel/activate helper tables

-- Legacy tables
CREATE TABLE IF NOT EXISTS tx_sender_cancel_try_to_send_outpoints (
    cancelled_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    vout INT NOT NULL,
    -- first observed chain height when this outpoint was seen spent (used for finality tracking)
    seen_at_height INT,
    is_finalized BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cancelled_id, txid, vout)
);

CREATE TABLE IF NOT EXISTS tx_sender_cancel_try_to_send_txids (
    cancelled_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    -- first observed chain height when this txid was seen confirmed (used for finality tracking)
    seen_at_height INT,
    is_finalized BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cancelled_id, txid)
);

CREATE TABLE IF NOT EXISTS tx_sender_activate_try_to_send_outpoints (
    activated_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    txid BYTEA NOT NULL,
    vout INT NOT NULL,
    timelock BIGINT NOT NULL,
    -- first observed chain height when this outpoint was seen spent (used for finality tracking)
    seen_at_height INT,
    is_finalized BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (activated_id, txid, vout)
);
