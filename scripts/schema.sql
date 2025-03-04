BEGIN;

-- Table to store the public keys of the verifiers
create table if not exists verifier_public_keys (
    idx int primary key,
    public_key text not null
);


create table if not exists operators (
    operator_idx int primary key,
    xonly_pk text not null,
    wallet_reimburse_address text not null,
    collateral_funding_outpoint text not null check (collateral_funding_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$')
);

-- Operator table for funding utxo used for deposits
create table if not exists funding_utxos (
    id serial primary key,
    funding_utxo jsonb not null,
    created_at timestamp not null default now()
);

-- Watchtower header chain proofs
create table if not exists header_chain_proofs (
    block_hash text primary key not null,
    block_header text,
    prev_block_hash text,
    height int not null,
    proof bytea
);

create table if not exists watchtower_xonly_public_keys (
    watchtower_id int not null,
    xonly_pk bytea not null,
    primary key (watchtower_id)
);

-- Verifier table of watchtower Winternitz public keys for every operator and deposit_id pair
create table if not exists watchtower_winternitz_public_keys (
    watchtower_id int not null,
    operator_id int not null,
    deposit_id int not null,
    winternitz_public_key bytea not null,
    primary key (watchtower_id, operator_id, deposit_id)
);

-- Verifier table of watchtower challenge addresses for every operator and deposit_id
create table if not exists watchtower_challenge_hashes (
    watchtower_id int not null,
    operator_id int not null,
    deposit_id int not null,
    challenge_hash bytea not null,
    primary key (watchtower_id, operator_id, deposit_id)
);

-- Verifier table of operators Winternitz public keys for every kickoff utxo for committing blockhash
create table if not exists operator_winternitz_public_keys (
    operator_id int not null,
    winternitz_public_keys bytea not null,
    primary key (operator_id)
);

create table if not exists deposits (
    deposit_id serial primary key,
    deposit_outpoint text unique not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    recovery_taproot_address text,
    evm_address text check (evm_address ~ '^[a-fA-F0-9]{40}')
);

-- Deposit signatures
create table if not exists deposit_signatures (
    deposit_id int not null references deposits (deposit_id),
    operator_idx int not null,
    round_idx int not null,
    kickoff_idx int not null,
    signatures bytea not null,
    primary key (deposit_id, operator_idx, round_idx, kickoff_idx)
);

-- Signatures of the operator for unspent kickoffs
create table if not exists unspent_kickoff_signatures (
    operator_idx int not null,
    round_idx int not null,
    signatures bytea not null,
    primary key (operator_idx, round_idx)
);

-- Verifier table for BitVM setup data
/* This table holds the BitVM setup data for each operator and deposit_id pair. */
create table if not exists bitvm_setups (
    operator_idx int not null,
    deposit_id int not null,
    assert_tx_addrs bytea[] not null,
    root_hash bytea not null check (length(root_hash) = 32),
    --public_input_wots bytea[] not null,
    created_at timestamp not null default now(),
    primary key (operator_idx, deposit_id)
);

-- Verifier table for the operators public digests to acknowledge watchtower challenges.
/* This table holds the public digests of the operators  to use for the watchtower
challenges for each (operator_idx, deposit_id) tuple. */
create table if not exists operators_challenge_ack_hashes (
    operator_idx int not null,
    deposit_id int not null,
    public_hashes bytea[] not null,
    created_at timestamp not null default now(),
    primary key (operator_idx, deposit_id)
);

-------- BITCOIN SYNCER --------

create table if not exists bitcoin_syncer (
    id serial primary key,
    blockhash text not null unique,
    prev_blockhash text not null,
    height int not null,
    is_canonical boolean not null default true
);

create table if not exists bitcoin_syncer_txs (
    block_id int not null references bitcoin_syncer (id),
    txid text not null,
    primary key (block_id, txid)
);

create table if not exists bitcoin_syncer_spent_utxos (
    block_id bigint not null references bitcoin_syncer (id),
    spending_txid text not null,
    txid text not null,
    vout bigint not null,
    primary key (block_id, spending_txid, txid, vout),
    foreign key (block_id, spending_txid) references bitcoin_syncer_txs (block_id, txid)
);

DO $$ 
begin
    if not exists (SELECT 1 FROM pg_type WHERE typname = 'bitcoin_syncer_event_type') then
        create type bitcoin_syncer_event_type AS ENUM ('new_block', 'reorged_block');
    end if;
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


-------- TX SENDER --------

DO $$ 
begin
    if not exists (SELECT 1 FROM pg_type WHERE typname = 'fee_paying_type') then
        create type bitcoin_syncer_event_type AS ENUM ('cpfp', 'rbf');
    end if;
END $$;

-- Table to store txs that needs to be fee bumped
create table if not exists tx_sender_try_to_send_txs (
    id serial primary key,
    raw_tx bytea not null,
    tx_data_for_logging text,
    fee_paying_type fee_paying_type not null,
    effective_fee_rate bigint,
    txid text check (txid ~ '^[a-fA-F0-9]{64}'), -- txid of the tx if it is CPFP
    seen_block_id int references bitcoin_syncer(id),
    latest_active_at timestamp,
    created_at timestamp not null default now()
);

create table if not exists tx_sender_rbf_txids (
    id int not null references tx_sender_try_to_send_txs(id),
    txid text not null check (txid ~ '^[a-fA-F0-9]{64}'),
    created_at timestamp not null default now(),
    primary key (id, txid)
);

-- Table to store fee payer UTXOs
create table if not exists tx_sender_fee_payer_utxos (
    id serial primary key,
    replacement_of_id int references tx_sender_fee_payer_utxos(id),
    bumped_id int not null references tx_sender_try_to_send_txs(id),
    fee_payer_txid text not null check (fee_payer_txid ~ '^[a-fA-F0-9]{64}'),
    vout int not null,
    amount bigint not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now()
);

create table if not exists tx_sender_cancel_try_to_send_outpoints (
    cancelled_id int not null references tx_sender_try_to_send_txs(id),
    txid text not null check (txid ~ '^[a-fA-F0-9]{64}'),
    vout int not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (cancelled_id, txid, vout)
);

create table if not exists tx_sender_cancel_try_to_send_txids (
    cancelled_id int not null references tx_sender_try_to_send_txs(id),
    txid text not null check (txid ~ '^[a-fA-F0-9]{64}'),
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (cancelled_id, txid)
);

create table if not exists tx_sender_activate_try_to_send_txids (
    activated_id int not null references tx_sender_try_to_send_txs(id),
    txid text not null check (txid ~ '^[a-fA-F0-9]{64}'),
    timelock bigint not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (activated_id, txid)
);

create table if not exists tx_sender_activate_try_to_send_outpoints (
    activated_id int not null references tx_sender_try_to_send_txs(id),
    txid text not null check (txid ~ '^[a-fA-F0-9]{64}'),
    vout int not null,
    timelock bigint not null,
    seen_block_id int references bitcoin_syncer(id),
    created_at timestamp not null default now(),
    primary key (activated_id, txid, vout)
);

-------- TX SENDER TRIGGERS --------

-- Trigger function for tx_sender_cancel_try_to_send_txids
CREATE OR REPLACE FUNCTION update_cancel_txids_seen_block_id()
RETURNS TRIGGER AS $$
BEGIN
    -- Find if this txid exists in a canonical block
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

-- Drop the trigger if it exists
DROP TRIGGER IF EXISTS trigger_update_cancel_txids_seen_block_id ON tx_sender_cancel_try_to_send_txids;

-- Create the trigger
CREATE TRIGGER trigger_update_cancel_txids_seen_block_id
AFTER INSERT ON tx_sender_cancel_try_to_send_txids
FOR EACH ROW
EXECUTE FUNCTION update_cancel_txids_seen_block_id();

-- Trigger function for tx_sender_cancel_try_to_send_outpoints
CREATE OR REPLACE FUNCTION update_cancel_outpoints_seen_block_id()
RETURNS TRIGGER AS $$
BEGIN
    -- Find if this outpoint is spent in a canonical block
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

-- Drop the trigger if it exists
DROP TRIGGER IF EXISTS trigger_update_cancel_outpoints_seen_block_id ON tx_sender_cancel_try_to_send_outpoints;

-- Create the trigger
CREATE TRIGGER trigger_update_cancel_outpoints_seen_block_id
AFTER INSERT ON tx_sender_cancel_try_to_send_outpoints
FOR EACH ROW
EXECUTE FUNCTION update_cancel_outpoints_seen_block_id();

-- Trigger function for tx_sender_activate_try_to_send_txids
CREATE OR REPLACE FUNCTION update_activate_txids_seen_block_id()
RETURNS TRIGGER AS $$
BEGIN
    -- Find if this txid exists in a canonical block
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

-- Drop the trigger if it exists
DROP TRIGGER IF EXISTS trigger_update_activate_txids_seen_block_id ON tx_sender_activate_try_to_send_txids;

-- Create the trigger
CREATE TRIGGER trigger_update_activate_txids_seen_block_id
AFTER INSERT ON tx_sender_activate_try_to_send_txids
FOR EACH ROW
EXECUTE FUNCTION update_activate_txids_seen_block_id();

-- Trigger function for tx_sender_activate_try_to_send_outpoints
CREATE OR REPLACE FUNCTION update_activate_outpoints_seen_block_id()
RETURNS TRIGGER AS $$
BEGIN
    -- Find if this outpoint is spent in a canonical block
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

-- Drop the trigger if it exists
DROP TRIGGER IF EXISTS trigger_update_activate_outpoints_seen_block_id ON tx_sender_activate_try_to_send_outpoints;

-- Create the trigger
CREATE TRIGGER trigger_update_activate_outpoints_seen_block_id
AFTER INSERT ON tx_sender_activate_try_to_send_outpoints
FOR EACH ROW
EXECUTE FUNCTION update_activate_outpoints_seen_block_id();


-------- ROUND MANAGMENT FOR OPERATOR --------

create table if not exists used_kickoff_connectors (
    round_idx int not null,
    kickoff_connector_idx int not null,
    kickoff_txid text check (kickoff_txid ~ '^[a-fA-F0-9]{64}'),
    created_at timestamp not null default now(),
    primary key (round_idx, kickoff_connector_idx)
);

create table if not exists current_round_index (
    id int primary key,
    round_idx int not null
);

INSERT INTO current_round_index (id, round_idx)
VALUES (1, 0)
ON CONFLICT DO NOTHING;


COMMIT;
