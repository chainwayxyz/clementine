CREATE TABLE IF NOT EXISTS bitcoin_syncer_txs (
    block_id int not null references bitcoin_syncer (id),
    txid bytea not null,
    primary key (block_id, txid)
);

CREATE INDEX IF NOT EXISTS bitcoin_syncer_txs_txid_idx ON bitcoin_syncer_txs(txid);

CREATE TABLE IF NOT EXISTS bitcoin_syncer_spent_utxos (
    block_id bigint not null references bitcoin_syncer (id),
    spending_txid bytea not null,
    txid bytea not null,
    vout bigint not null,
    primary key (block_id, spending_txid, txid, vout),
    foreign key (block_id, spending_txid) references bitcoin_syncer_txs (block_id, txid)
);
