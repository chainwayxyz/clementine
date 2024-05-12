begin;

create table new_deposit_requests (
    id serial primary key, 
    start_utxo text not null,
    recovery_taproot_address text not null,
    evm_address text not null check (evm_address ~ '^[a-fA-F0-9]{40}'),
    created_at timestamp not null default now()
);

CREATE SEQUENCE start_from_zero MINVALUE 0 START 0;

create table deposit_move_txs (
    id INTEGER primary key default nextval('start_from_zero'),
    start_utxo text not null,
    recovery_taproot_address text not null,
    evm_address text not null check (evm_address ~ '^[a-fA-F0-9]{40}'),
    move_txid text not null unique check (move_txid ~ '^[a-fA-F0-9]{64}'),
    created_at timestamp not null default now()
);

create table withdrawal_sigs (
    idx INTEGER primary key,
    bridge_fund_txid text not
     null check (bridge_fund_txid ~ '^[a-fA-F0-9]{64}'),
    sig text not null check (sig ~ '^[a-fA-F0-9]{128}'),
    created_at timestamp not null default now()
);

commit;
