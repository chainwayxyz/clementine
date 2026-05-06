CREATE TABLE IF NOT EXISTS finalized_block_fetcher_progress (
    consumer_handle text primary key,
    last_processed_height int not null,
    last_processed_block_hash text,
    created_at timestamp not null default now(),
    updated_at timestamp not null default now()
);

ALTER TABLE finalized_block_fetcher_progress
    ADD COLUMN IF NOT EXISTS last_processed_block_hash text;
