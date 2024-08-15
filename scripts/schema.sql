begin;

-- Verifier table for deposit details
/* This table holds the information related to a deposit. */
create table deposit_infos (
    id INTEGER primary key,
    deposit_outpoint text not null check (deposit_request_outpoint ~ '^[a-fA-F0-9]{64}:\\d+'),
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
create table nonces (
    idx INTEGER primary key,
    deposit_outpoint text primary key not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:\\d+'),
    pub_nonce text not null check (pub_nonce ~ '^[a-fA-F0-9]{132}'),
    sec_nonce text not null check (sec_nonce ~ '^[a-fA-F0-9]{128}'),
    agg_nonce text check (agg_nonce ~ '^[a-fA-F0-9]{132}'),
    sig_hash text check (sig_hash ~ '^[a-fA-F0-9]{64}'), /* 32 bytes */
    created_at timestamp not null default now()
)

-- Verifier table for kickoff o for deposits
/* This table holds the kickoff utxos sent by the operators for each deposit. */
create table deposit_kickoff_utxos (
    id INTEGER primary key,
    deposit_outpoint text not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:\\d+'),
    kickoff_utxo text not null,
    created_at timestamp not null default now()
);

-- Operator table for kickoff utxo and funding utxo for deposits
/* This table holds the funding utxos sent by the operators for each deposit. */
create table deposit_kickoff_funding_outpoints (
    deposit_outpoint text primary key not null check (deposit_outpoint ~ '^[a-fA-F0-9]{64}:\\d+'),
    kickoff_outpoint text not null check (kickoff_outpoint ~ '^[a-fA-F0-9]{64}:\\d+'),
    created_at timestamp not null default now()
);

-- Operator table for funding utxo used for deposits TODO: Change this table
create table funding_utxos (
    id INTEGER primary key,
    funding_utxo text not null,
    created_at timestamp not null default now()
);

commit;
