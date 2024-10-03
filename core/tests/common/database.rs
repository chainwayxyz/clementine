//! # Database Mock Interface
//!
//! This module provides mock database interfaces, for testing.

use clementine_core::{
    config::BridgeConfig, database::Database, errors::BridgeError, utils::initialize_logger,
};

use super::common;
use std::thread;

/// Creates a temporary database for testing.
///
/// # Parameters
///
/// - db_name: New database's name.
/// - config_file: Test configuration file. Rest of the config will be read from
///   here and only `db_name` will be overwritten.
///
/// Returns new `BridgeConfig`.
pub async fn create_test_config(db_name: &str, config_file: &str) -> BridgeConfig {
    // Use maximum log level for tests.
    initialize_logger(5).unwrap();

    let mut config = common::get_test_config(config_file).unwrap();
    config.db_name = db_name.to_owned();
    initialize_database(&config).await.unwrap();

    config
}

/// Creates a temporary database for testing, using current thread's name as the
/// database name.
///
/// # Parameters
///
/// - config_file: Test configuration file. Rest of the config will be read from
///   here and only `db_name` will be overwritten.
/// - suffix: Optional suffix added to the thread handle.
///
/// # Returns
///
/// `BridgeConfig`
pub async fn create_test_config_with_thread_name(
    config_file: &str,
    suffix: Option<&str>,
) -> BridgeConfig {
    let suffix: String = suffix.unwrap_or(&String::default()).to_string();

    let handle = thread::current()
        .name()
        .unwrap()
        .split(':')
        .last()
        .unwrap()
        .to_owned()
        + &suffix;

    create_test_config(&handle, config_file).await
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
pub async fn initialize_database(config: &BridgeConfig) -> Result<(), BridgeError> {
    drop_database(config).await?;

    create_database(config).await?;

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

#[cfg(test)]
mod tests {
    use crate::common::{
        common::get_test_config,
        database::{self, create_database, drop_database},
    };
    use clementine_core::database::Database;

    #[tokio::test]
    async fn create_drop_database() {
        let mut config = get_test_config("test_config.toml").unwrap();
        config.db_name = "create_drop_database".to_string();

        // Drop database (clear previous test run artifacts) and check that
        // connection can't be established.
        drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());

        // It should be possible to connect new database after creating it.
        create_database(&config).await.unwrap();
        Database::new(&config).await.unwrap();

        // Dropping database again should result connection to not be
        // established.
        drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());
    }

    #[tokio::test]
    async fn initialize_database() {
        let mut config = get_test_config("test_config.toml").unwrap();
        config.db_name = "initialize_database".to_string();

        // Drop database (clear previous test run artifacts) and check that
        // connection can't be established.
        drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());

        // It should be possible to initialize and connect to the new database.
        database::initialize_database(&config).await.unwrap();
        Database::new(&config).await.unwrap();

        // Dropping database again should result connection to not be
        // established.
        drop_database(&config).await.unwrap();
        assert!(Database::new(&config).await.is_err());
    }
}
