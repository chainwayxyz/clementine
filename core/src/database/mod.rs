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
    ///
    /// TODO: Pass the reference &BridgeConfig instead of copying BridgeConfig.
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let url = Database::get_postgresql_database_url(&config);

        match sqlx::PgPool::connect(&url).await {
            Ok(connection) => Ok(Self { connection }),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Closes database connection.
    pub async fn close(&self) {
        self.connection.close().await;
    }

    /// Prepares a valid PostgreSQL URL.
    ///
    /// URL contains user, password, host and password fields, which are picked
    /// from given configuration.
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
    /// URL contains host, port, database name, user and password fields, which
    /// are picked from given configuration.
    fn get_postgresql_database_url(config: &BridgeConfig) -> String {
        Database::get_postgresql_url(config) + "/" + &config.db_name
    }

    /// Initializes a new database with given configuration. If the database is
    /// already initialized, it will be dropped before initialization. Meaning,
    /// a clean state is guaranteed.
    ///
    /// [`Database::new`] must be called after this to connect to the
    /// initialized database.
    pub async fn initialize_database(config: &BridgeConfig) -> Result<(), BridgeError> {
        // Clear artifacts.
        Database::drop_database(config).await?;

        // Create new database with correct owner.
        Database::create_database(config).await?;

        // Run schema SQL script to initialize database.
        Database::run_schema_script(config).await?;

        Ok(())
    }

    /// Drops a database with given name, if it exists.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection. Won't return any errors if database already not exists.
    async fn drop_database(config: &BridgeConfig) -> Result<(), BridgeError> {
        let url = Database::get_postgresql_url(config);
        let conn = sqlx::PgPool::connect(url.as_str()).await?;

        let query = format!("DROP DATABASE IF EXISTS {}", &config.db_name);
        sqlx::query(&query).execute(&conn).await?;

        conn.close().await;
        Ok(())
    }

    /// Drops a database with given name, if it exists.
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

    /// Drops a database with given name, if it exists.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection.
    async fn run_schema_script(config: &BridgeConfig) -> Result<(), BridgeError> {
        let database = Database::new(config.clone()).await?;

        sqlx::raw_sql(include_str!("../../../scripts/schema.sql"))
            .execute(&database.connection)
            .await?;

        database.close().await;
        Ok(())
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
    use std::thread;

    #[tokio::test]
    async fn valid_database_connection() {
        let config = create_test_config_with_thread_name("test_config.toml", None).await;

        Database::new(config).await.unwrap();
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

        Database::new(config).await.unwrap();
    }

    #[tokio::test]
    async fn create_drop_database() {
        let handle = thread::current()
            .name()
            .unwrap()
            .split(':')
            .last()
            .unwrap()
            .to_owned();
        let mut config = common::get_test_config("test_config.toml").unwrap();
        config.db_name = handle.clone();
        Database::initialize_database(&config).await.unwrap();

        // Do not save return result so that connection will drop immediately.
        Database::new(config.clone()).await.unwrap();

        Database::drop_database(&config).await.unwrap();
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
