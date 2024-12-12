//! # Mock

/// Creates a temporary database for testing, using current thread's name as the
/// database name.
///
/// # Parameters
///
/// - `config_file`: Test configuration file in `str` type. Rest of the config
///   will be read from here and only `db_name` will be overwritten.
/// - `suffix`: Optional suffix added to the thread handle in `Option<str>`
///   type.
///
/// # Returns
///
/// - [`BridgeConfig`]: Modified configuration struct
///
/// # Required Imports
///
/// ## Unit Tests
///
/// ```rust
/// use crate::{config::BridgeConfig, utils::initialize_logger};
/// use crate::database::Database;
/// use std::{env, thread};
/// ```
///
/// ## Integration Tests And Binaries
#[macro_export]
macro_rules! create_test_config_with_thread_name {
    ($config_file:expr, $suffix:expr) => {{
        let suffix = $suffix.unwrap_or(&String::default()).to_string();

        let handle = thread::current()
            .name()
            .unwrap()
            .split(':')
            .last()
            .unwrap()
            .to_owned()
            + &suffix;

        // Use maximum log level for tests.
        initialize_logger(5).unwrap();

        // Read specified configuration file from `tests/data` directory.
        let mut config = BridgeConfig::try_parse_file(
            format!("{}/tests/data/{}", env!("CARGO_MANIFEST_DIR"), $config_file).into(),
        )
        .unwrap();

        // Check environment for an overwrite config. TODO: Convert this to env vars.
        let env_config: Option<BridgeConfig> = if let Ok(config_file_path) = env::var("TEST_CONFIG")
        {
            Some(BridgeConfig::try_parse_file(config_file_path.into()).unwrap())
        } else {
            None
        };

        // Overwrite user's environment to test's hard coded data if environment
        // file is specified.
        if let Some(env_config) = env_config {
            config.db_host = env_config.db_host;
            config.db_port = env_config.db_port;
            config.db_user = env_config.db_user;
            config.db_password = env_config.db_password;
            config.db_name = env_config.db_name;
        };

        config.db_name = handle.to_string();
        Database::initialize_database(&config).await.unwrap();

        config
    }};
}
