BEGIN;
create table if not exists operators (
    xonly_pk text primary key not null,
    wallet_reimburse_address text not null,
    collateral_funding_outpoint text not null check (
        collateral_funding_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'
    )
);
create table if not exists bitcoin_blocks (
    height int primary key not null,
    block_hash text not null,
    block_data bytea not null,
    created_at timestamp not null default now()
);
-- Watchtower header chain proofs
create table if not exists header_chain_proofs (
    block_hash text primary key not null,
    block_header text,
    prev_block_hash text,
    height bigint not null,
    proof bytea
);
create table if not exists watchtower_xonly_public_keys (
    watchtower_id int not null,
    xonly_pk bytea not null,
    primary key (watchtower_id)
);
-- Verifier table of operators Winternitz public keys for every kickoff utxo for committing blockhash
create table if not exists operator_winternitz_public_keys (
    xonly_pk text primary key not null,
    winternitz_public_keys bytea not null
);
-- Verifier table of operators Winternitz public keys for every kickoff utxo for committing bitvm inputs
create table if not exists operator_bitvm_winternitz_public_keys (
    xonly_pk text not null,
    deposit_id int not null,
    bitvm_winternitz_public_keys bytea not null,
    primary key (xonly_pk, deposit_id)
);
create table if not exists deposits (
    deposit_id serial primary key,
    deposit_outpoint text unique not null check (
        deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'
    ),
    deposit_params bytea,
    move_to_vault_txid bytea
);
-- Deposit signatures
create table if not exists deposit_signatures (
    deposit_id int not null references deposits (deposit_id),
    operator_xonly_pk text not null,
    round_idx int not null,
    kickoff_idx int not null,
    kickoff_txid bytea,
    signatures bytea not null,
    primary key (
        deposit_id,
        operator_xonly_pk,
        round_idx,
        kickoff_idx
    )
);
-- Signatures of the operator for unspent kickoffs
create table if not exists unspent_kickoff_signatures (
    xonly_pk text not null,
    round_idx int not null,
    signatures bytea not null,
    primary key (xonly_pk, round_idx)
);
-- LCP and storage proofs saved for sending assert
create table if not exists lcp_for_asserts (
    deposit_id int not null primary key,
    lcp_receipt bytea not null
);
-- Verifier table for BitVM setup data
/* This table holds the BitVM setup data for each operator and deposit_id pair. */
create table if not exists bitvm_setups (
    xonly_pk text not null,
    deposit_id int not null,
    assert_tx_addrs bytea [] not null,
    root_hash bytea not null check (length(root_hash) = 32),
    latest_blockhash_root_hash bytea not null check (length(latest_blockhash_root_hash) = 32),
    --public_input_wots bytea[] not null,
    created_at timestamp not null default now(),
    primary key (xonly_pk, deposit_id)
);
-- Verifier table for the operators public digests to acknowledge watchtower challenges.
/* This table holds the public digests of the operators  to use for the watchtower
 challenges for each (xonly_pk, deposit_id) tuple. */
create table if not exists operators_challenge_ack_hashes (
    xonly_pk text not null,
    deposit_id int not null,
    public_hashes bytea [] not null,
    created_at timestamp not null default now(),
    primary key (xonly_pk, deposit_id)
);
/*******************************************************************************
 *                               BITCOIN SYNCER
 ******************************************************************************/
create table if not exists bitcoin_syncer (
    id serial primary key,
    blockhash text not null unique,
    prev_blockhash text not null,
    height int not null,
    is_canonical boolean not null default true
);
create table if not exists bitcoin_syncer_txs (
    block_id int not null references bitcoin_syncer (id),
    txid bytea not null,
    primary key (block_id, txid)
);
create table if not exists bitcoin_syncer_spent_utxos (
    block_id bigint not null references bitcoin_syncer (id),
    spending_txid bytea not null,
    txid bytea not null,
    vout bigint not null,
    primary key (block_id, spending_txid, txid, vout),
    foreign key (block_id, spending_txid) references bitcoin_syncer_txs (block_id, txid)
);
create table if not exists bitcoin_blocks (
    height int primary key not null,
    block_hash text not null,
    block_data bytea not null,
    created_at timestamp not null default now()
);
-- enum for bitcoin_syncer_events
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'bitcoin_syncer_event_type'
) THEN CREATE TYPE bitcoin_syncer_event_type AS ENUM ('new_block', 'reorged_block');
END IF;
END $$;
create table if not exists bitcoin_syncer_events (
    id serial primary key,
    block_id int not null references bitcoin_syncer (id),
    event_type bitcoin_syncer_event_type not null,
    created_at timestamp not null default now()
);
create table if not exists bitcoin_syncer_event_handlers (
    consumer_handle text not null,
    last_processed_event_id int not null,
    created_at timestamp not null default now(),
    primary key (consumer_handle)
);
/*******************************************************************************
 *                                 TX SENDER
 ******************************************************************************/
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'fee_paying_type'
) THEN CREATE TYPE fee_paying_type AS ENUM ('cpfp', 'rbf', 'nofunding');
END IF;
END $$;
-- Transactions that are needed to be fee bumped
create table if not exists tx_sender_try_to_send_txs (
    id serial primary key,
    raw_tx bytea not null,
    tx_metadata text,
    fee_paying_type fee_paying_type not null,
    effective_fee_rate bigint,
    txid bytea,
    -- txid of the tx if it is CPFP
    seen_block_id int references bitcoin_syncer(id),
    latest_active_at timestamp,
    created_at timestamp not null default now(),
    rbf_signing_info text
);
create table if not exists tx_sender_rbf_txids (
    insertion_order serial not null,
    id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    created_at timestamp not null default now(),
    primary key (id, txid)
);
create table if not exists tx_sender_fee_payer_utxos (
    id serial primary key,
    -- null for first created tx, then the id of first created tx for all replacements
    replacement_of_id int references tx_sender_fee_payer_utxos(id),
    bumped_id int not null references tx_sender_try_to_send_txs(id),
    fee_payer_txid bytea not null,
    vout int not null,
    amount bigint not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now()
);
create table if not exists tx_sender_cancel_try_to_send_outpoints (
    cancelled_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    vout int not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (cancelled_id, txid, vout)
);
create table if not exists tx_sender_cancel_try_to_send_txids (
    cancelled_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (cancelled_id, txid)
);
create table if not exists tx_sender_activate_try_to_send_txids (
    activated_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    timelock bigint not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (activated_id, txid)
);
create table if not exists tx_sender_activate_try_to_send_outpoints (
    activated_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    vout int not null,
    timelock bigint not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (activated_id, txid, vout)
);
-- Triggers that sets the seen_block_id to the block id of the canonical block
-- when a row inserted to the tx_sender_*_try_to_send_* tables.
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
/*******************************************************************************
 *           FINALIZED BLOCK SYNCER, CITREA DEPOSITS AND WITHDRAWALS
 ******************************************************************************/
create table if not exists withdrawals (
    idx int primary key,
    move_to_vault_txid bytea not null,
    withdrawal_utxo_txid bytea,
    withdrawal_utxo_vout int,
    withdrawal_batch_proof_bitcoin_block_height int,
    payout_txid bytea,
    payout_payer_operator_xonly_pk text,
    payout_tx_blockhash text check (payout_tx_blockhash ~ '^[a-fA-F0-9]{64}'),
    is_payout_handled boolean not null default false,
    kickoff_txid bytea,
    created_at timestamp not null default now()
);
-- Add state machine tables at the end of the file:
-- State machines table to store serialized machines
CREATE TABLE IF NOT EXISTS state_machines (
    id SERIAL PRIMARY KEY,
    machine_type VARCHAR(50) NOT NULL,
    -- 'kickoff' or 'round'
    state_json TEXT NOT NULL,
    kickoff_id TEXT NULL,
    -- only for kickoff machines
    operator_xonly_pk TEXT NULL,
    -- only for round machines
    owner_type VARCHAR(100) NOT NULL DEFAULT 'default',
    -- Type of the owner managing this state machine
    block_height INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(machine_type, kickoff_id, owner_type),
    -- For kickoff machines
    UNIQUE(machine_type, operator_xonly_pk, owner_type) -- For round machines
);
-- Status table to track the last processed block
CREATE TABLE IF NOT EXISTS state_manager_status (
    owner_type VARCHAR(100) PRIMARY KEY,
    next_height_to_process INT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS state_machines_block_height_idx ON state_machines(block_height);
CREATE INDEX IF NOT EXISTS state_machines_machine_type_idx ON state_machines(machine_type);
CREATE INDEX IF NOT EXISTS state_machines_kickoff_id_idx ON state_machines(kickoff_id)
WHERE kickoff_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS state_machines_operator_xonly_pk_idx ON state_machines(operator_xonly_pk)
WHERE operator_xonly_pk IS NOT NULL;
CREATE INDEX IF NOT EXISTS state_machines_owner_type_idx ON state_machines(owner_type);
COMMIT;
/*******************************************************************************
 *                           ROUND MANAGEMENT FOR OPERATOR
 ******************************************************************************/
create table if not exists used_kickoff_connectors (
    round_idx int not null,
    kickoff_connector_idx int not null,
    kickoff_txid bytea,
    created_at timestamp not null default now(),
    primary key (round_idx, kickoff_connector_idx)
);
create table if not exists current_round_index (
    id int primary key,
    round_idx int not null
);
INSERT INTO current_round_index (id, round_idx)
VALUES (1, 0) ON CONFLICT DO NOTHING;
COMMIT;
-- Table to store submission errors
CREATE TABLE IF NOT EXISTS tx_sender_debug_submission_errors (
    id SERIAL PRIMARY KEY,
    tx_id INT NOT NULL REFERENCES tx_sender_try_to_send_txs(id),
    error_message TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
-- Table to store TX sending state
CREATE TABLE IF NOT EXISTS tx_sender_debug_sending_state (
    tx_id INT PRIMARY KEY REFERENCES tx_sender_try_to_send_txs(id),
    state TEXT NOT NULL,
    -- 'waiting_for_fee_payer_utxos', 'ready_to_send', 'sent', etc.
    last_update TIMESTAMP NOT NULL DEFAULT NOW(),
    activated_timestamp TIMESTAMP -- the time when the conditions for this tx were satisfied - null if the conditions are not satisfied.
);
-- Index for faster queries
CREATE INDEX IF NOT EXISTS tx_sender_debug_submission_errors_tx_id_idx ON tx_sender_debug_submission_errors(tx_id);
-- Table to store emergency stop signatures
CREATE TABLE IF NOT EXISTS emergency_stop_sigs (
    move_txid bytea primary key not null,
    emergency_stop_tx bytea not null,
    created_at timestamp not null default now()
);
COMMIT;