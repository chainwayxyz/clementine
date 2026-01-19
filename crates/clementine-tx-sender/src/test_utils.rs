//! Test utilities for clementine-tx-sender.

use crate::config::TxSenderPostgresConfig;
use crate::TxSenderDb;

/// Sets up a test database with a unique name based on the current test thread name.
///
/// This function follows the same pattern as `core::test::common::create_test_config_with_thread_name`:
/// it extracts the thread name, creates a unique database name, drops/creates the database,
/// and runs migrations.
///
/// # Panics
///
/// Panics if:
/// - The thread name cannot be retrieved
/// - Database connection fails
/// - Database operations fail
#[cfg(feature = "test-utils")]
pub async fn setup_txsender_test_db() -> TxSenderDb {
    use secrecy::ExposeSecret;

    let handle = std::thread::current()
        .name()
        .expect("Failed to get thread name")
        .split(':')
        .next_back()
        .expect("Failed to get thread name")
        .to_owned();

    let db_name = format!("clementine_tx_sender_test_{handle}");

    // Use same defaults as core test util
    let admin_config = TxSenderPostgresConfig {
        host: "127.0.0.1".to_string(),
        port: 5432,
        user: "clementine".to_string().into(),
        password: "clementine".to_string().into(),
        dbname: "postgres".to_string(),
    };

    // Connect to postgres database to create/drop the test database
    let admin_db = TxSenderDb::connect(&admin_config)
        .await
        .expect("Failed to connect to postgres database");

    // Drop and create the test database
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db_name}"))
        .execute(admin_db.pool())
        .await
        .expect("Failed to drop test database");

    sqlx::query(&format!(
        "CREATE DATABASE {} WITH OWNER {}",
        db_name,
        admin_config.user.expose_secret()
    ))
    .execute(admin_db.pool())
    .await
    .expect("Failed to create test database");

    admin_db.pool().close().await;

    // Connect to the test database
    let test_config = TxSenderPostgresConfig {
        dbname: db_name,
        ..admin_config
    };

    let db = TxSenderDb::connect(&test_config)
        .await
        .expect("Failed to connect to test database");
    db.run_migrations().await.expect("Failed to run migrations");
    db
}
