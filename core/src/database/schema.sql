BEGIN;
create table if not exists operators (
    xonly_pk text primary key not null,
    wallet_reimburse_address text not null,
    collateral_funding_outpoint text not null check (
        collateral_funding_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'
    )
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
-- Legacy Bitcoin Syncer table kept so older migrations can run after schema.sql bootstrap.
-- 0002 reads bitcoin_syncer for seen_block_id backfills, and migrations 0004/0006 join it for old LCP progress.
create table if not exists bitcoin_syncer (
    id serial primary key,
    blockhash text not null unique,
    prev_blockhash text not null,
    height int not null,
    is_canonical boolean not null default true
);
-- Legacy Bitcoin Syncer event enum kept for older migrations.
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'bitcoin_syncer_event_type'
) THEN CREATE TYPE bitcoin_syncer_event_type AS ENUM ('new_block', 'reorged_block');
END IF;
END $$;
-- Legacy Bitcoin Syncer event table kept so migrations 0004/0006 can read old events.
create table if not exists bitcoin_syncer_events (
    id serial primary key,
    block_id int not null references bitcoin_syncer (id),
    event_type bitcoin_syncer_event_type not null,
    created_at timestamp not null default now()
);
-- Legacy Bitcoin Syncer handler table kept so migration 0006 can migrate old handler progress.
create table if not exists bitcoin_syncer_event_handlers (
    consumer_handle text not null,
    last_processed_event_id int not null,
    created_at timestamp not null default now(),
    primary key (consumer_handle)
);
create table if not exists finalized_block_fetcher_progress (
    consumer_handle text primary key,
    last_processed_height int not null,
    last_processed_block_hash text not null,
    created_at timestamp not null default now(),
    updated_at timestamp not null default now()
);
/*******************************************************************************
 *                                 TX SENDER
 ******************************************************************************/
DO $$ BEGIN IF NOT EXISTS (
    SELECT 1
    FROM pg_type
    WHERE typname = 'fee_paying_type'
) THEN CREATE TYPE fee_paying_type AS ENUM ('cpfp', 'rbf', 'rbf_wtxid_grind', 'nofunding');
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
    -- first observed chain height when tx was seen confirmed (used for finality tracking)
    seen_at_height int,
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
    -- first observed chain height when fee payer tx was seen confirmed (used for finality tracking)
    seen_at_height int,
    created_at timestamp not null default now(),
    -- if set to false, all replacements of this fee payer utxo are evicted
    is_evicted boolean not null default false
);
-- Legacy tx-sender table kept so migrations 0002 and 0003 can run before 0005 drops it.
create table if not exists tx_sender_cancel_try_to_send_outpoints (
    cancelled_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    vout int not null,
    -- first observed chain height when this outpoint was seen spent (used for finality tracking)
    seen_at_height int,
    created_at timestamp not null default now(),
    primary key (cancelled_id, txid, vout)
);
-- Legacy tx-sender table kept so migrations 0002 and 0003 can run before 0005 drops it.
create table if not exists tx_sender_cancel_try_to_send_txids (
    cancelled_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    -- first observed chain height when this txid was seen confirmed (used for finality tracking)
    seen_at_height int,
    created_at timestamp not null default now(),
    primary key (cancelled_id, txid)
);
create table if not exists tx_sender_activate_try_to_send_txids (
    activated_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    timelock bigint not null,
    -- first observed chain height when this txid was seen confirmed (used for finality tracking)
    seen_at_height int,
    -- whether the activation txid is currently present in the mempool
    in_mempool boolean not null default false,
    created_at timestamp not null default now(),
    primary key (activated_id, txid)
);
-- Legacy tx-sender table kept so migrations 0002 and 0003 can run before 0005 drops it.
create table if not exists tx_sender_activate_try_to_send_outpoints (
    activated_id int not null references tx_sender_try_to_send_txs(id),
    txid bytea not null,
    vout int not null,
    timelock bigint not null,
    -- first observed chain height when this outpoint was seen spent (used for finality tracking)
    seen_at_height int,
    created_at timestamp not null default now(),
    primary key (activated_id, txid, vout)
);
-- Citrea raw transaction queue for DA payloads.
--
-- Each logical request is grouped by `insertion_id`. For non-chunked payloads
-- there is a single row. For chunked payloads, multiple chunk rows plus a
-- single aggregate row share the same `insertion_id`.
--
-- `body_hash` is globally unique (when non-NULL) to avoid queuing duplicate blobs.
create sequence if not exists tx_sender_citrea_raw_tx_insertion_id_seq;
create table if not exists tx_sender_citrea_raw_tx_queue (
    id bigserial primary key,
    -- group identifier shared across all rows belonging to the same rawtxdata
    -- request (chunks and aggregate).
    insertion_id bigint not null default nextval('tx_sender_citrea_raw_tx_insertion_id_seq'),
    -- numeric transaction kind as defined in `citrea::transactionkind` (u16).
    transaction_kind smallint not null,
    -- raw body bytes. non-null for all non-aggregate rows; null for the
    -- aggregate placeholder row.
    body bytea,
    -- optional hash of body used for deduplication (e.g. SHA-256).
    body_hash bytea,
    -- optional commit outpoint once known (format: "txid:vout").
    commit_outpoint text,
    -- optional link to a tx_sender_try_to_send_txs row once it exists.
    try_to_send_id int references tx_sender_try_to_send_txs(id),
    -- whether the aggregate row has been finalized and should no longer be processed.
    aggregate_finalized boolean not null default false,
    created_at timestamp not null default now(),
    unique (body_hash)
);
create index if not exists tx_sender_citrea_raw_tx_queue_insertion_id_idx on tx_sender_citrea_raw_tx_queue(insertion_id);
create index if not exists tx_sender_citrea_raw_tx_queue_try_to_send_id_idx on tx_sender_citrea_raw_tx_queue(try_to_send_id);
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
-- Legacy state manager status kept so older migrations can run after
-- schema.sql bootstrap; migration 0006 moves this progress to finalized block
-- cursor progress while keeping this table for rollback compatibility.
CREATE TABLE IF NOT EXISTS state_manager_status (
    owner_type VARCHAR(100) PRIMARY KEY,
    next_height_to_process INT NOT NULL,
    last_processed_lcp INT,
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
