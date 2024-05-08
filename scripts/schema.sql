begin;

create table new_deposit_requests (
    start_utxo text,
    recovery_taproot_address text,
    evm_address text
);

CREATE SEQUENCE start_from_zero MINVALUE 0 START 0;

create table deposit_move_txs (
    id INTEGER primary key default nextval('start_from_zero'),
    move_txid text not null unique check (move_txid ~ '^[a-fA-F0-9]{64}')
);

commit;
