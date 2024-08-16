BEGIN;

-- Verifier table for deposit details
/* This table holds the information related to a deposit. */
create table deposit_infos (
    id serial primary key,
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    recovery_taproot_address text not null,
    evm_address text not null check (evm_address ~ '^[a-fA-F0-9]{40}'),
    created_at timestamp not null default now()
);

-- Verifier table for operator signatures, operator will read from here and send the take tx
create table operator_take_sigs (
    id serial primary key,
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    bridge_fund_txout text not null,
    operator_index int not null,
    sig text not null,
    created_at timestamp not null default now()
);

-- Verifier table for nonces related to deposits
/* This table holds the public, secret, and aggregated nonces related to a deposit.
For each deposit, we have (2 + num_operators) nonce triples. The first triple is for 
move_commit_tx, the second triple is for move_reveal_tx, and the rest is for operator_takes_tx
for each operator. Also for each triple, we hold the sig_hash to be signed to prevent reuse
of the nonces. */ 
create table nonces (
    idx serial primary key,
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    pub_nonce text not null check (pub_nonce ~ '^[a-fA-F0-9]{132}'),
    sec_nonce text not null check (sec_nonce ~ '^\\x[a-fA-F0-9]{128}$'),
    agg_nonce text check (agg_nonce ~ '^[a-fA-F0-9]{132}'),
    sig_hash text check (sig_hash ~ '^[a-fA-F0-9]{64}'), /* 32 bytes */
    created_at timestamp not null default now()
);

CREATE OR REPLACE FUNCTION prevent_sig_hash_update()
RETURNS TRIGGER AS $$
BEGIN
    -- If the old value of sig_hash is not NULL and the new value is different, raise an exception
    IF OLD.sig_hash IS NOT NULL AND NEW.sig_hash IS DISTINCT FROM OLD.sig_hash THEN
        RAISE EXCEPTION 'sig_hash cannot be updated once it has a value';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create the trigger
CREATE TRIGGER prevent_sig_hash_update_trigger
BEFORE UPDATE ON nonces
FOR EACH ROW
EXECUTE FUNCTION prevent_sig_hash_update();

-- Verifier table for kickoff for deposits
/* This table holds the kickoff utxos sent by the operators for each deposit. */
create table deposit_kickoff_utxos (
    id serial primary key,
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    kickoff_utxo text not null,
    created_at timestamp not null default now(),
    unique (deposit_outpoint, kickoff_utxo)
);

-- Operator table for kickoff utxo and funding utxo for deposits
/* This table holds the funding utxos sent by the operators for each deposit. */
create table deposit_kickoff_generator_txs (
    id serial primary key,
    txid text not null check (txid ~ '^[a-fA-F0-9]{64}'),
    raw_signed_tx text not null,
    num_kickoffs int not null,
    cur_unused_kickoff_index int not null,
    funding_txid text not null check (funding_txid ~ '^[a-fA-F0-9]{64}'),
    created_at timestamp not null default now()
);

-- Operator table for kickoff utxo related to deposits
/* This table holds the kickoff utxos sent by the operators for each deposit. */
create table operators_kickoff_utxo (
    deposit_outpoint text primary key not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:(0|[1-9][0-9]{0,9})$'),
    kickoff_utxo text not null,
    created_at timestamp not null default now()
);

-- Operator table for funding utxo used for deposits 
create table funding_utxos (
    id serial primary key,
    funding_utxo text not null,
    created_at timestamp not null default now()
);

COMMIT;
