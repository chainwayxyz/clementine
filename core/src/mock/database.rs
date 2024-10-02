//! # Database Mock Interface
//!
//! This module provides mock database interfaces, for testing.

use super::common;
use crate::{config::BridgeConfig, database::Database, utils::initialize_logger};
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
    Database::initialize_database(&config).await.unwrap();

    let database = Database::new(config.clone()).await.unwrap();
    database.init_from_schema().await.unwrap();
    database.close().await;

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
