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

/// Holds data about the connected PostgreSQL database.
#[derive(Clone, Debug)]
pub struct Database {
    connection: Pool<Postgres>,
}

impl Database {
    /// Connects to the PostgreSQL database with given configuration. Returns
    /// [`Database`] if database is accessible.
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

    /// Closes current database connection.
    pub async fn close(&self) {
        self.connection.close().await;
    }

    /// Creates a new database with given name. A new database connection should
    /// be established after with `Database::new(config)` call after this.
    ///
    /// This will drop the target database if it exist.
    ///
    /// Returns a new `BridgeConfig` with updated database name. Use that
    /// `BridgeConfig` to create a new connection, using `Database::new()`.
    pub async fn create_database(
        config: BridgeConfig,
        database_name: &str,
    ) -> Result<BridgeConfig, BridgeError> {
        let url = Database::get_postgresql_url(&config);
        let conn = sqlx::PgPool::connect(url.as_str()).await?;
        Database::drop_database(config.clone(), database_name).await?;
        let query = format!(
            "CREATE DATABASE {} WITH OWNER {}",
            database_name, config.db_user
        );
        sqlx::query(&query).execute(&conn).await?;

        conn.close().await;

        let config = BridgeConfig {
            db_name: database_name.to_string(),
            ..config
        };

        Ok(config)
    }

    /// Drops a database with given name, if it exists.
    ///
    /// # Errors
    ///
    /// Will return [`BridgeError`] if there was a problem with database
    /// connection.
    pub async fn drop_database(
        config: BridgeConfig,
        database_name: &str,
    ) -> Result<(), BridgeError> {
        let url = Database::get_postgresql_url(&config);
        let conn = sqlx::PgPool::connect(url.as_str()).await?;

        let query = format!("DROP DATABASE IF EXISTS {database_name}");
        sqlx::query(&query).execute(&conn).await?;

        conn.close().await;

        Ok(())
    }

    /// Prepares a valid PostgreSQL URL.
    ///
    /// URL contains host, user and password fields, which are picked from given
    /// configuration.
    fn get_postgresql_url(config: &BridgeConfig) -> String {
        "postgresql://".to_owned()
            + &config.db_user
            + ":"
            + &config.db_password
            + "@"
            + &config.db_host
    }

    /// Prepares a valid PostgreSQL URL to a specific database.
    ///
    /// URL contains host, port, database name, user and password fields, which
    /// are picked from given configuration.
    fn get_postgresql_database_url(config: &BridgeConfig) -> String {
        "postgresql://".to_owned()
            + &config.db_host
            + ":"
            + &config.db_port.to_string()
            + "?dbname="
            + &config.db_name
            + "&user="
            + &config.db_user
            + "&password="
            + &config.db_password
    }

    /// Runs given SQL string to database. Database connection must be established
    /// before calling this function.
    pub async fn run_sql(&self, raw_sql: &str) -> Result<(), BridgeError> {
        sqlx::raw_sql(raw_sql).execute(&self.connection).await?;

        Ok(())
    }

    pub async fn init_from_schema(&self) -> Result<(), BridgeError> {
        let schema = include_str!("../../../scripts/schema.sql");
        self.run_sql(schema).await
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
        let config = common::get_test_config("test_config.toml").unwrap();
        let config = Database::create_database(config, &handle).await.unwrap();

        // Do not save return result so that connection will drop immediately.
        Database::new(config.clone()).await.unwrap();

        Database::drop_database(config, &handle).await.unwrap();
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
            "postgresql://iam:sofun@parties"
        );
    }

    #[test]
    fn get_postgresql_database_url() {
        let mut config = BridgeConfig::new();

        config.db_user = "butforgot".to_string();
        config.db_name = "bitcoins".to_string();
        config.db_port = 45;
        config.db_password = "help".to_string();
        config.db_host = "ihave".to_string();

        assert_eq!(
            &Database::get_postgresql_database_url(&config),
            "postgresql://ihave:45?dbname=bitcoins&user=butforgot&password=help"
        );
    }
}
