//! # Database Mock Interface
//!
//! This module provides mock database interfaces, for testing.

/// Creates a temporary database for testing.
///
/// Parameters:
///
/// - db_name: New database's name.
/// - config_file: Test configuration file. Rest of the config will be read from
/// here and only `db_name` will be overwritten.
///
/// Returns new `BridgeConfig`.
#[macro_export]
macro_rules! create_test_config {
    ($db_name:expr, $config_file:expr) => {{
        let mut config = common::get_test_config($config_file).unwrap();
        config.bitcoin_rpc_url = $db_name.clone();
        let config = Database::create_database(config, &$db_name).await.unwrap();

        let database = Database::new(config.clone()).await.unwrap();
        database
            .run_sql_file("../scripts/schema.sql")
            .await
            .unwrap();

        database.close().await;

        config
    }};
}

/// Creates a temporary database for testing, using current thread's name as the
/// database name.
///
/// Parameters:
///
/// - config_file: Test configuration file. Rest of the config will be read from
/// here and only `db_name` will be overwritten.
///
/// Returns new `BridgeConfig`.
#[macro_export]
macro_rules! create_test_config_with_thread_name {
    ($config_file:expr) => {{
        let handle = thread::current()
            .name()
            .unwrap()
            .split(":")
            .last()
            .unwrap()
            .to_owned();

        create_test_config!(handle, $config_file)
    }};
}
