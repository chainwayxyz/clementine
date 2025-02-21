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

-- Verifier table for deposit details
/* This table holds the information related to a deposit. */
create table if not exists deposit_infos (
    deposit_outpoint text primary key not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    recovery_taproot_address text not null,
    evm_address text not null check (evm_address ~ '^[a-fA-F0-9]{40}'),
    created_at timestamp not null default now()
);

-- Verifier table for nonces related to deposits
/* This table holds the public, secret, and aggregated nonces related to a deposit.
For each deposit, we have (2 + num_operators) nonce triples. The first triple is for
move_commit_tx, the second triple is for move_reveal_tx, and the rest is for operator_takes_tx
for each operator. Also for each triple, we hold the sig_hash to be signed to prevent reuse
of the nonces. */
create table if not exists nonces (
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    internal_idx int not null,
    pub_nonce bytea not null check (length(pub_nonce) = 66),
    agg_nonce bytea check (length(agg_nonce) = 66),
    sighash bytea check (length(sighash) = 32),
    partial_sig bytea check (length(partial_sig) = 32),
    created_at timestamp not null default now(),
    primary key (deposit_outpoint, internal_idx)
);

CREATE OR REPLACE FUNCTION prevent_sighash_update()
RETURNS TRIGGER AS $$
BEGIN
    -- If the old value of sig_hash is not NULL and the new value is different, raise an exception
    IF OLD.sighash IS NOT NULL AND NEW.sighash IS DISTINCT FROM OLD.sighash THEN
        RAISE EXCEPTION 'sighash cannot be updated once it has a value';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create the trigger if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'prevent_sighash_update_trigger'
    ) THEN
        CREATE TRIGGER prevent_sighash_update_trigger
        BEFORE UPDATE ON nonces
        FOR EACH ROW
        EXECUTE FUNCTION prevent_sighash_update();
    END IF;
END $$;

-- Verifier table for kickoff for deposits
/* This table holds the kickoff utxos sent by the operators for each deposit. */
create table if not exists deposit_kickoff_utxos (
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    operator_idx int not null,
    kickoff_utxo jsonb not null,
    slash_or_take_sig text,
    operator_take_sig bytea,
    burn_sig text,
    created_at timestamp not null default now(),
    primary key (deposit_outpoint, operator_idx)
);

-- Operator table for kickoff utxo and funding utxo for deposits
/* This table holds the funding utxos sent by the operators for each deposit. */
create table if not exists deposit_kickoff_generator_txs (
    id serial primary key,
    txid text unique not null check (txid ~ '^[a-fA-F0-9]{64}'),
    raw_signed_tx text not null,
    num_kickoffs int not null,
    cur_unused_kickoff_index int not null check (cur_unused_kickoff_index <= num_kickoffs),
    funding_txid text not null check (funding_txid ~ '^[a-fA-F0-9]{64}'),
    created_at timestamp not null default now()
);

-- Operator table for kickoff utxo related to deposits
/* This table holds the kickoff utxos sent by the operators for each deposit. */
create table if not exists operators_kickoff_utxo (
    deposit_outpoint text primary key not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    kickoff_utxo jsonb not null,
    created_at timestamp not null default now()
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
create table if not exists watchtower_challenge_addresses (
    watchtower_id int not null,
    operator_id int not null,
    deposit_id int not null,
    challenge_address bytea not null,
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
    deposit_outpoint text unique not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$')
);

-- Deposit signatures
create table if not exists deposit_signatures (
    deposit_id int not null,
    operator_idx int not null,
    round_idx int not null,
    kickoff_idx int not null,
    signatures bytea not null,
    primary key (deposit_id, operator_idx, round_idx, kickoff_idx)
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

-- enum for bitcoin_syncer_events
create type bitcoin_syncer_event_type as enum ('new_block', 'reorged_block');

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


create type fee_paying_type as enum ('cpfp', 'rbf');

-- Table to store txs that needs to be fee bumped
create table if not exists tx_sender_try_to_send_txs (
    id serial primary key,
    raw_tx bytea not null,
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

COMMIT;
