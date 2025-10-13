# Migrations

For migrations, [SQLx migrate](https://docs.rs/sqlx/latest/sqlx/migrate/index.html) is used.

## How to Add a New Migration File

1. Create a new migration SQL file with `.up.sql` extension (and optionally `.down.sql` for rollback)
2. Migration files must be lexicographically ordered - increment the prefix number from the latest migration (e.g., if latest is `0001_init.up.sql`, create `0002_your_migration.up.sql`)
3. Migrations are applied automatically on startup in crate::Database::run_schema_script

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
