begin;

create table new_deposit_requests (
    id serial primary key, 
    start_utxo text not null,
    recovery_taproot_address text not null,
    evm_address text not null check (evm_address ~ '^[a-fA-F0-9]{40}'),
    created_at timestamp not null default now()
);

CREATE SEQUENCE start_from_zero MINVALUE 0 START 0;

create table deposit_flow_infos (
    id INTEGER primary key default nextval('start_from_zero'),
    deposit_request_utxo text not null,
    recovery_taproot_address text not null,
    evm_address text not null check (evm_address ~ '^[a-fA-F0-9]{40}'),
    move_intermediate_txid text not null unique check (move_txid ~ '^[a-fA-F0-9]{64}'),
    bridge_fund_txid text not null unique check (bridge_fund_txid ~ '^[a-fA-F0-9]{64}'),
    created_at timestamp not null default now()
);

create table withdrawal_sigs (
    idx INTEGER primary key,
    bridge_fund_txid text not
     null check (bridge_fund_txid ~ '^[a-fA-F0-9]{64}'),
    sig text not null check (sig ~ '^[a-fA-F0-9]{128}'),
    created_at timestamp not null default now()
);


create table nonces (
    idx INTEGER primary key,
    deposit_utxo text primary key not null check (deposit_txid ~ '^[a-fA-F0-9]{64}:\\d+'),
    pub_nonce text not null check (pub_nonce ~ '^[a-fA-F0-9]{132}'),
    sec_nonce text not null check (sec_nonce ~ '^[a-fA-F0-9]{128}'),
    agg_nonce text check (agg_nonce ~ '^[a-fA-F0-9]{132}'),
    sig_hash text check (sig_hash ~ '^[a-fA-F0-9]{64}'), /* 32 bytes,  */
)

commit;
