//! # Database Operations
//!
//! Database crate provides functions that adds/reads values from PostgreSQL
//! database.
//!
//! **Warning:** This crate won't configure PostgreSQL itself and excepts admin
//! privileges to create/drop databases.

use std::time::Duration;

use crate::config::BridgeConfig;
use clementine_errors::BridgeError;
use eyre::Context;
use secrecy::ExposeSecret;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions;
use sqlx::{Pool, Postgres};

mod aggregator;
mod bitcoin_syncer;
mod header_chain_prover;
mod operator;
#[cfg(feature = "automation")]
mod state_machine;
#[cfg(all(test, feature = "automation"))]
mod test;
#[cfg(feature = "automation")]
mod tx_sender;
mod verifier;
mod wrapper;

#[cfg(test)]
pub use wrapper::*;

/// Assuming total of 100 max connections as default, the verifier and operator
/// can share 50 each.
pub const MAX_CONNECTIONS_FOR_POOL: u32 = 50;

/// PostgreSQL database connection details.
#[derive(Clone, Debug)]
pub struct Database {
    connection: Pool<Postgres>,
}

/// Database transaction for Postgres.
pub type DatabaseTransaction<'a, 'b> = &'a mut sqlx::Transaction<'b, Postgres>;

/// Executes a query with a transaction if it is provided.
///
/// # Parameters
///
/// - `$conn`: Database connection.
/// - `$tx`: Optional database transaction
/// - `$query`: Query to execute.
/// - `$method`: Method to execute on the query.
#[macro_export]
macro_rules! execute_query_with_tx {
    ($conn:expr, $tx:expr, $query:expr, $method:ident) => {
        match $tx {
            Some(tx) => $query.$method(&mut **tx).await,
            None => $query.$method(&$conn).await,
        }
    };
}

impl Database {
    /// Establishes a new connection to a PostgreSQL database with given
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`BridgeError`] if database is not accessible.
    pub async fn new(config: &BridgeConfig) -> Result<Self, BridgeError> {
        let mut opt = PgConnectOptions::default();
        opt = opt.host(config.db_host.as_str());
        opt = opt.port(
            u16::try_from(config.db_port).wrap_err("Failed to convert database port to u16")?,
        );
        opt = opt.username(config.db_user.expose_secret());
        opt = opt.password(config.db_password.expose_secret());
        opt = opt.database(config.db_name.as_str());
        // Change default sqlx warnings from Warn to Debug
        // These logs really clutter our CI logs, and they were never useful.
        // But in the future if we fix slow statements (if they are actually a problem?), we can revert this.
        opt = opt.log_slow_statements(log::LevelFilter::Debug, Duration::from_secs(3));

        let opts = sqlx::postgres::PgPoolOptions::new()
            .acquire_slow_level(log::LevelFilter::Debug)
            .max_connections(MAX_CONNECTIONS_FOR_POOL);

        #[cfg(test)]
        let opts = if config.test_params.timeout_params.any_timeout() {
            // increase timeout for pool connections beyond any other to avoid flakiness
            opts.acquire_timeout(Duration::from_secs(10000))
                .acquire_slow_threshold(Duration::from_secs(10000))
        } else {
            opts
        };

        let connection = opts
            .connect_with(opt)
            .await
            .map_err(BridgeError::DatabaseError)?;

        Ok(Self { connection })
    }

    /// Closes database connection.
    pub async fn close(&self) {
        self.connection.close().await;
    }

    pub fn get_pool(&self) -> Pool<Postgres> {
        self.connection.clone()
    }

    pub async fn is_pgmq_installed(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<bool, BridgeError> {
        let query = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'pgmq' AND table_name = 'meta'"
        );

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        Ok(result.0 > 0)
    }

    /// Runs the schema script on a database for the given configuration.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection.
    pub async fn run_schema_script(
        config: &BridgeConfig,
        is_verifier: bool,
    ) -> Result<(), BridgeError> {
        let database = Database::new(config).await?;

        sqlx::raw_sql(include_str!("schema.sql"))
            .execute(&database.connection)
            .await?;
        if is_verifier {
            // Check if PGMQ schema already exists
            let is_pgmq_installed = database.is_pgmq_installed(None).await?;

            // Only execute PGMQ setup if it doesn't exist
            if !is_pgmq_installed {
                sqlx::raw_sql(include_str!("pgmq.sql"))
                    .execute(&database.connection)
                    .await?;
            }
        }

        // Apply embedded SQLx migrations from the migrations folder
        // This looks for SQL files under core/src/database/migrations at compile time
        // SQL files in migration folder will be applied in lexicographical order of their filenames
        static MIGRATOR: Migrator = sqlx::migrate!("src/database/migrations");

        MIGRATOR
            .run(&database.connection)
            .await
            .wrap_err("Failed to run migrations")?;

        database.close().await;
        Ok(())
    }

    /// Starts a database transaction.
    ///
    /// Return value can be used for committing changes. If not committed,
    /// database will rollback every operation done after that call.
    pub async fn begin_transaction(
        &self,
    ) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, BridgeError> {
        Ok(self.connection.begin().await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::test::common::*;
    use crate::{config::BridgeConfig, database::Database};

    #[tokio::test]
    async fn valid_database_connection() {
        let config = create_test_config_with_thread_name().await;

        Database::new(&config).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn invalid_database_connection() {
        let mut config = BridgeConfig::new();
        config.db_host = "nonexistinghost".to_string();
        config.db_name = "nonexistingpassword".to_string();
        config.db_user = "nonexistinguser".to_string().into();
        config.db_password = "nonexistingpassword".to_string().into();
        config.db_port = 123;

        Database::new(&config).await.unwrap();
    }
}
