//! # Database Operations
//!
//! Database crate provides functions that adds/reads values from PostgreSQL
//! database.
//!
//! **Warning:** This crate won't configure PostgreSQL itself and excepts admin
//! privileges to create/drop databases.

use crate::{config::BridgeConfig, errors::BridgeError};
use sqlx::{Pool, Postgres};

mod common;
mod wrapper;

/// PostgreSQL database connection details.
#[derive(Clone, Debug)]
pub struct Database {
    connection: Pool<Postgres>,
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

    /// Initializes a new database with given configuration. If the database is
    /// already initialized, it will be dropped before initialization. Meaning,
    /// a clean state is guaranteed.
    ///
    /// [`Database::new`] must be called after this to connect to the
    /// initialized database.
    ///
    /// **Warning:** This must not be used in release environments and is only
    /// suitable for testing.
    ///
    /// TODO: This function must be marked with `#[cfg(test)]` to prevent it
    /// from infiltrating the binaries. See:
    /// https://github.com/chainwayxyz/clementine/issues/181
    pub async fn initialize_database(config: &BridgeConfig) -> Result<(), BridgeError> {
        Database::drop_database(config).await?;

        Database::create_database(config).await?;

        Database::run_schema_script(config).await?;

        Ok(())
    }

    /// Creates a new database with given configuration.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection.
    async fn create_database(config: &BridgeConfig) -> Result<(), BridgeError> {
        let url = Database::get_postgresql_url(config);
        let conn = sqlx::PgPool::connect(url.as_str()).await?;

        sqlx::query(&format!(
            "CREATE DATABASE {} WITH OWNER {}",
            config.db_name, config.db_user
        ))
        .execute(&conn)
        .await?;

        conn.close().await;
        Ok(())
    }

    /// Drops the database for the given configuration, if it exists.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection. It won't return any errors if the database does not already
    /// exist.
    async fn drop_database(config: &BridgeConfig) -> Result<(), BridgeError> {
        let url = Database::get_postgresql_url(config);
        let conn = sqlx::PgPool::connect(url.as_str()).await?;

        let query = format!("DROP DATABASE IF EXISTS {}", &config.db_name);
        sqlx::query(&query).execute(&conn).await?;

        conn.close().await;
        Ok(())
    }

    /// Runs the schema script on a database for the given configuration.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection.
    pub async fn run_schema_script(config: &BridgeConfig) -> Result<(), BridgeError> {
        let database = Database::new(config).await?;

        sqlx::raw_sql(include_str!("../../../scripts/schema.sql"))
            .execute(&database.connection)
            .await?;

        database.close().await;
        Ok(())
    }

    /// Prepares a valid PostgreSQL URL.
    ///
    /// URL contains user, password, host and port fields, which are picked from
    /// the given configuration.
    fn get_postgresql_url(config: &BridgeConfig) -> String {
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
    fn get_postgresql_database_url(config: &BridgeConfig) -> String {
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
    use crate::{
        config::BridgeConfig,
        database::Database,
        mock::{common, database::create_test_config_with_thread_name},
    };

    #[tokio::test]
    async fn valid_database_connection() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;

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

    #[tokio::test]
    async fn create_drop_database() {
        let mut config = common::get_test_config("test_config.toml").unwrap();
        config.db_name = "create_drop_database".to_string();

        // Drop database (clear previous test run artifacts) and check that
        // connection can't be established.
        Database::drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());

        // It should be possible to connect new database after creating it.
        Database::create_database(&config).await.unwrap();
        Database::new(&config).await.unwrap();

        // Dropping database again should result connection to not be
        // established.
        Database::drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());
    }

    #[tokio::test]
    async fn initialize_database() {
        let mut config = common::get_test_config("test_config.toml").unwrap();
        config.db_name = "initialize_database".to_string();

        // Drop database (clear previous test run artifacts) and check that
        // connection can't be established.
        Database::drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());

        // It should be possible to initialize and connect to the new database.
        Database::initialize_database(&config).await.unwrap();
        Database::new(&config).await.unwrap();

        // Dropping database again should result connection to not be
        // established.
        Database::drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());
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
