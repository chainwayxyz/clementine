CREATE TABLE IF NOT EXISTS finalized_block_fetcher_progress (
    consumer_handle text primary key,
    last_processed_height int not null,
    last_processed_block_hash text not null,
    created_at timestamp not null default now(),
    updated_at timestamp not null default now()
);
