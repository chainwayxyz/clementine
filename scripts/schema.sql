begin;

create table deposit_transactions (
    start_utxo text,
    return_address text,
    evm_address text
);

commit;
