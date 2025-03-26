//! # Database Operations
//!
//! Database crate provides functions that adds/reads values from PostgreSQL
//! database.
//!
//! **Warning:** This crate won't configure PostgreSQL itself and excepts admin
//! privileges to create/drop databases.

use crate::{config::BridgeConfig, errors::BridgeError};
use sqlx::{Pool, Postgres};

mod bitcoin_syncer;
mod header_chain_prover;
mod operator;
mod state_machine;
mod tx_sender;
mod verifier;
mod wrapper;

#[cfg(test)]
pub use wrapper::*;

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
        let url = Database::get_postgresql_database_url(config);

        match sqlx::PgPool::connect(&url).await {
            Ok(connection) => Ok(Self { connection }),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Closes database connection.
    pub async fn close(&self) {
        self.connection.close().await;
    }

    pub fn get_pool(&self) -> Pool<Postgres> {
        self.connection.clone()
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

        sqlx::raw_sql(include_str!("../../../scripts/schema.sql"))
            .execute(&database.connection)
            .await?;
        if is_verifier {
            sqlx::raw_sql(include_str!("../../../scripts/pgmq.sql"))
                .execute(&database.connection)
                .await?;
        }

        database.close().await;
        Ok(())
    }

    /// Prepares a valid PostgreSQL URL.
    ///
    /// URL contains user, password, host and port fields, which are picked from
    /// the given configuration.
    pub fn get_postgresql_url(config: &BridgeConfig) -> String {
        "postgresql://".to_owned()
            + &config.db_user
            + ":"
            + &config.db_password
            + "@"
            + &config.db_host
            + ":"
            + &config.db_port.to_string()
    }

    /// Prepares a valid PostgreSQL URL to a specific database.
    ///
    /// URL contains user, password, host, port and database name fields, which
    /// are picked from the given configuration.
    pub fn get_postgresql_database_url(config: &BridgeConfig) -> String {
        Database::get_postgresql_url(config) + "/" + &config.db_name
    }

    /// Starts a database transaction.
    ///
    /// Return value can be used for committing changes. If not committed,
    /// database will rollback every operation done after that call.
    pub async fn begin_transaction(
        &self,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
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
        config.db_user = "nonexistinguser".to_string();
        config.db_password = "nonexistingpassword".to_string();
        config.db_port = 123;

        Database::new(&config).await.unwrap();
    }

    #[test]
    fn get_postgresql_url() {
        let mut config = BridgeConfig::new();

        config.db_password = "sofun".to_string();
        config.db_port = 45;
        config.db_user = "iam".to_string();
        config.db_host = "parties".to_string();

        assert_eq!(
            &Database::get_postgresql_url(&config),
            "postgresql://iam:sofun@parties:45"
        );
    }

    #[test]
    fn get_postgresql_database_url() {
        let mut config = BridgeConfig::new();

        config.db_name = "times".to_string();
        config.db_password = "funnier".to_string();
        config.db_port = 45;
        config.db_user = "butyouare".to_string();
        config.db_host = "parties".to_string();

        assert_eq!(
            &Database::get_postgresql_database_url(&config),
            "postgresql://butyouare:funnier@parties:45/times"
        );
    }
}
