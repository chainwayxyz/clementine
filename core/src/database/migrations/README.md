# Migrations

For migrations, [SQLx migrate](https://docs.rs/sqlx/latest/sqlx/migrate/index.html) is used.

## How to Add a New Migration File

Migration files must be lexicographically ordered - increment the prefix number from the latest migration (e.g., if latest is `0001_init.up.sql`, create `0002_your_migration.up.sql`).

Migrations are applied automatically on startup in `crate::Database::run_schema_script`

1. Create a new migration SQL file with `.up.sql` extension (and optionally `.down.sql` for rollback)
2. Put the files in `core/src/database/migrations`

```rust
static MIGRATOR: Migrator = sqlx::migrate!("src/database/migrations");

MIGRATOR
    .run(&database.connection)
    .await
    .wrap_err("Failed to run migrations")?;
```

## Example migration files

`0001_add_sent_block_id.up.sql`

```sql
ALTER TABLE tx_sender_try_to_send_txs
ADD COLUMN IF NOT EXISTS sent_block_id INT DEFAULT NULL;
```

`0001_add_send_block_id.down.sql`

```sql
ALTER TABLE tx_sender_try_to_send_txs DROP COLUMN IF EXISTS sent_block_id;
```

## Testing Migrations Locally

Migrations can be tested locally using [sqlx-cli](https://crates.io/crates/sqlx-cli):

```bash
# Install sqlx-cli
cargo install sqlx-cli --no-default-features --features postgres

# Run migrations
sqlx migrate run --source <path_to_migrations_folder>

# Revert last migration
sqlx migrate revert
```
