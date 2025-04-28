//! # Command Line Interface
//!
//! This module defines command line interface for binaries. `Clap` is used
//! for easy generation of help messages and handling arguments.

use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::utils;
use crate::utils::delayed_panic;
use clap::Parser;
use clap::ValueEnum;
use eyre::Context;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::level_filters::LevelFilter;
use tracing::Level;

#[derive(Debug, Clone, Copy, ValueEnum, Eq, PartialEq)]
pub enum Actors {
    Verifier,
    Operator,
    Aggregator,
}

/// Clementine (C) 2025 Chainway Limited
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Actor to run.
    pub actor: Actors,
    /// TOML formatted configuration file.
    pub config_file: Option<PathBuf>,
    /// TOML formatted protocol parameters file.
    pub protocol_params_file: Option<PathBuf>,
    /// Verbosity level, ranging from 0 (none) to 5 (highest)
    #[arg(short, long, default_value_t = 3)]
    pub verbose: u8,
}

/// Parse given iterator. This is good for isolated environments, like tests.
fn parse_from<I, T>(itr: I) -> Result<Args, BridgeError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Args::try_parse_from(itr) {
        Ok(c) => Ok(c),
        Err(e) => Err(BridgeError::ConfigError(e.to_string())),
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConfigSource {
    File(PathBuf),
    Env,
}
/// Selects a configuration source for the main config or the protocol paramset.
///
/// Configuration can be loaded either from a file specified by a path in the CLI args,
/// or from environment variables.
///
/// Selection logic is as follows:
///
/// 1. If the named environment variable (eg. `READ_CONFIG_FROM_ENV`) is not set
///    or if the named environment variable is set to `0` or `off`, we use the file
///    path provided in the CLI args (fail if not provided)
///
/// 2. If the named environment variable is set to `1` or `on`, we explicitly read from the
///    environment variable
///
/// 3. If the named environment variable is set to an unknown value, we print a
///    warning and default to environment variables
///
/// # Examples
///
/// ```bash
/// # Load config from a file and protocol params from a file
/// READ_CONFIG_FROM_ENV=0 READ_PARAMSET_FROM_ENV=0 clementine-core verifier --config-file /path/to/config.toml --protocol-params-file /path/to/protocol-params.toml
///
/// # or
/// # define all config variables in the environment
/// export CONFIG_ONE=1
/// export PARAM_ONE=1
/// # and source from environment variables
/// READ_CONFIG_FROM_ENV=1 READ_PARAMSET_FROM_ENV=1 clementine-core verifier
///
/// # or
/// # source paramset from environment variables but use config from a file
/// export PARAM_ONE=1
/// export PARAM_TWO=1
/// READ_CONFIG_FROM_ENV=0 READ_PARAMSET_FROM_ENV=1 clementine-core verifier --config-file /path/to/config.toml
///
/// # WRONG usage (will use environment variables for both config and paramset)
/// export CONFIG_ONE=1
/// export PARAM_ONE=1
/// READ_CONFIG_FROM_ENV=1 READ_PARAMSET_FROM_ENV=1 clementine-core --config-file /path/to/config.toml --protocol-params-file /path/to/protocol-params.toml
/// ```
pub fn get_config_source(
    read_from_env_name: &'static str,
    provided_arg: Option<PathBuf>,
) -> Result<ConfigSource, BridgeError> {
    Ok(match std::env::var(read_from_env_name) {
        Err(_) => ConfigSource::File(provided_arg.ok_or(BridgeError::ConfigError(
            "No file path or environment variable provided for config file.".to_string(),
        ))?),
        Ok(str) if str == "0" || str == "off" => ConfigSource::File(provided_arg.ok_or(
            BridgeError::ConfigError("No file path provided for config file.".to_string()),
        )?),
        Ok(str) => {
            if str != "1" || str != "on" {
                tracing::warn!("Unknown value for {read_from_env_name}: {str}. Expected 1/0/off/on. Defaulting to environment variables.");
            }

            if provided_arg.is_some() {
                tracing::warn!("File path provided in CLI arguments while {read_from_env_name} is set to 1. Ignoring provided file path and reading from environment variables.");
            }

            ConfigSource::Env
        }
    })
}

/// Gets configuration using CLI arguments, for binaries. If there are any errors, prints
/// error and panics.
///
/// Steps:
///
/// 1. Get CLI arguments
/// 2. Initialize logger
/// 3. Get configuration, either from environment variables or
///    configuration file
/// 4. Get protocol parameters, either from environment variables or
///    protocol parameters file
///
/// # Returns
///
/// A tuple, containing:
///
/// - [`BridgeConfig`] from CLI argument
/// - [`Args`] from CLI options
pub fn get_cli_config() -> (BridgeConfig, Args) {
    let args = env::args();

    match get_cli_config_from_args(args) {
        Ok(config) => config,
        Err(e) => {
            delayed_panic!("Failed to get CLI config: {e:?}");
        }
    }
}

/// Wrapped function for tests
fn get_cli_config_from_args<I, T>(itr: I) -> Result<(BridgeConfig, Args), BridgeError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = parse_from(itr).wrap_err("Failed to parse CLI arguments.")?;

    let level_filter = match args.verbose {
        0 => None,
        other => Some(LevelFilter::from_level(
            Level::from_str(&other.to_string()).unwrap_or(Level::INFO),
        )),
    };

    utils::initialize_logger(level_filter).wrap_err("Failed to initialize logger.")?;

    let config_source = get_config_source("READ_CONFIG_FROM_ENV", args.config_file.clone());

    let mut config =
        match config_source.wrap_err("Failed to determine source for configuration.")? {
            ConfigSource::File(config_file) => {
                // Read from configuration file ONLY
                BridgeConfig::try_parse_file(config_file)
                    .wrap_err("Failed to read configuration from file.")?
            }
            ConfigSource::Env => BridgeConfig::from_env()
                .wrap_err("Failed to read configuration from environment variables.")?,
        };

    let protocol_params_source =
        get_config_source("READ_PARAMSET_FROM_ENV", args.protocol_params_file.clone())
            .wrap_err("Failed to determine source for protocol parameters.")?;

    // Leaks memory to get a static reference to the paramset
    // This is needed to reduce copies of the protocol paramset when passing it around.
    // This is fine, since this will only run once in the lifetime of the program.
    let paramset: &'static ProtocolParamset = Box::leak(Box::new(match protocol_params_source {
        ConfigSource::File(path) => ProtocolParamset::from_toml_file(path.as_path())
            .wrap_err("Failed to read protocol parameters from file.")?,
        ConfigSource::Env => ProtocolParamset::from_env()
            .wrap_err("Failed to read protocol parameters from environment.")?,
    }));

    // The default will be REGTEST_PARAMSET and is overridden from the selected source above.
    config.protocol_paramset = paramset;

    Ok((config, args))
}

#[cfg(test)]
mod tests {
    use super::{get_cli_config_from_args, get_config_source, parse_from, ConfigSource};
    use crate::cli::Actors;
    use crate::errors::BridgeError;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;

    /// With help message flag, we should see the help message. Shocking.
    #[test]
    fn help_message() {
        match parse_from(vec!["clementine-core", "--help"]) {
            Ok(_) => panic!("expected configuration error"),
            Err(BridgeError::ConfigError(e)) => println!("{e}"),
            e => panic!("unexpected error {e:#?}"),
        }
    }

    /// With version flag, we should see the program version read from
    /// `Cargo.toml`.
    #[test]
    fn version() {
        match parse_from(vec!["clementine-core", "--version"]) {
            Ok(_) => panic!("expected configuration error"),
            Err(BridgeError::ConfigError(e)) => println!("{e}"),
            e => panic!("unexpected error {e:#?}"),
        }
    }

    // Helper function to set and unset environment variables for tests
    fn with_env_var<F, T>(name: &str, value: Option<&str>, test: F) -> T
    where
        F: FnOnce() -> T,
    {
        let prev_value = env::var(name).ok();
        match value {
            Some(val) => env::set_var(name, val),
            None => env::remove_var(name),
        }
        let result = test();
        match prev_value {
            Some(val) => env::set_var(name, val),
            None => env::remove_var(name),
        }
        result
    }

    #[test]
    fn test_get_config_source_env_not_set() {
        with_env_var("TEST_READ_FROM_ENV", None, || {
            let path = PathBuf::from("/path/to/config");
            let result = get_config_source("TEST_READ_FROM_ENV", Some(path.clone()));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::File(path));

            // When path is not provided, should return error
            let result = get_config_source("TEST_READ_FROM_ENV", None);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), BridgeError::ConfigError(_)));
        })
    }

    #[test]
    fn test_get_config_source_env_set_to_off() {
        // Test with "0"
        with_env_var("TEST_READ_FROM_ENV", Some("0"), || {
            let path = PathBuf::from("/path/to/config");
            let result = get_config_source("TEST_READ_FROM_ENV", Some(path.clone()));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::File(path));

            // When path is not provided, should return error
            let result = get_config_source("TEST_READ_FROM_ENV", None);
            assert!(result.is_err());
        });

        // Test with "off"
        with_env_var("TEST_READ_FROM_ENV", Some("off"), || {
            let path = PathBuf::from("/path/to/config");
            let result = get_config_source("TEST_READ_FROM_ENV", Some(path.clone()));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::File(path));
        })
    }

    #[test]
    fn test_get_config_source_env_set_to_on() {
        // Test with "1"
        with_env_var("TEST_READ_FROM_ENV", Some("1"), || {
            let result = get_config_source("TEST_READ_FROM_ENV", None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::Env);

            // Even if path is provided, should still return Env
            let path = PathBuf::from("/path/to/config");
            let result = get_config_source("TEST_READ_FROM_ENV", Some(path));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::Env);
        });

        // Test with "on"
        with_env_var("TEST_READ_FROM_ENV", Some("on"), || {
            let result = get_config_source("TEST_READ_FROM_ENV", None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::Env);
        })
    }

    #[test]
    fn test_get_config_source_env_unknown_value() {
        with_env_var("TEST_READ_FROM_ENV", Some("invalid"), || {
            let result = get_config_source("TEST_READ_FROM_ENV", None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ConfigSource::Env);
        })
    }

    // Helper to create a temporary config file
    fn with_temp_config_file<F, T>(content: &str, test: F) -> T
    where
        F: FnOnce(PathBuf) -> T,
    {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_config.toml");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        let result = test(file_path);
        temp_dir.close().unwrap();
        result
    }

    // Helper to set up all environment variables needed for config
    fn setup_config_env_vars() {
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", "17000");
        env::set_var(
            "SECRET_KEY",
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        env::set_var("OPERATOR_WITHDRAWAL_FEE_SATS", "100000");
        env::set_var("BITCOIN_RPC_URL", "http://127.0.0.1:18443/wallet/admin");
        env::set_var("BITCOIN_RPC_USER", "admin");
        env::set_var("BITCOIN_RPC_PASSWORD", "admin");
        env::set_var("DB_HOST", "127.0.0.1");
        env::set_var("DB_PORT", "5432");
        env::set_var("DB_USER", "clementine");
        env::set_var("DB_PASSWORD", "clementine");
        env::set_var("DB_NAME", "clementine");
        env::set_var("CITREA_RPC_URL", "");
        env::set_var("CITREA_LIGHT_CLIENT_PROVER_URL", "");
        env::set_var(
            "BRIDGE_CONTRACT_ADDRESS",
            "3100000000000000000000000000000000000002",
        );
    }

    // Helper to clean up all environment variables
    fn cleanup_config_env_vars() {
        env::remove_var("HOST");
        env::remove_var("PORT");
        env::remove_var("SECRET_KEY");
        env::remove_var("OPERATOR_WITHDRAWAL_FEE_SATS");
        env::remove_var("BITCOIN_RPC_URL");
        env::remove_var("BITCOIN_RPC_USER");
        env::remove_var("BITCOIN_RPC_PASSWORD");
        env::remove_var("DB_HOST");
        env::remove_var("DB_PORT");
        env::remove_var("DB_USER");
        env::remove_var("DB_PASSWORD");
        env::remove_var("DB_NAME");
        env::remove_var("CITREA_RPC_URL");
        env::remove_var("CITREA_LIGHT_CLIENT_PROVER_URL");
        env::remove_var("BRIDGE_CONTRACT_ADDRESS");
    }

    // Basic minimum toml config content
    const MINIMAL_CONFIG_CONTENT: &str = r#"
host = "127.0.0.1"
port = 17000
secret_key = "1111111111111111111111111111111111111111111111111111111111111111"
operator_withdrawal_fee_sats = 100000
bitcoin_rpc_url = "http://127.0.0.1:18443/wallet/admin"
bitcoin_rpc_user = "admin"
bitcoin_rpc_password = "admin"
db_host = "127.0.0.1"
db_port = 5432
db_user = "clementine"
db_password = "clementine"
db_name = "clementine"
citrea_rpc_url = ""
citrea_light_client_prover_url = ""
bridge_contract_address = "3100000000000000000000000000000000000002"
"#;

    #[test]
    fn test_get_cli_config_file_mode() {
        with_env_var("READ_CONFIG_FROM_ENV", Some("0"), || {
            with_temp_config_file(MINIMAL_CONFIG_CONTENT, |config_path| {
                let args = vec![
                    "clementine-core",
                    "verifier",
                    "--config-file",
                    config_path.to_str().unwrap(),
                ];

                let result = get_cli_config_from_args(args);
                assert!(result.is_ok());

                let (config, cli_args) = result.unwrap();
                assert_eq!(config.host, "127.0.0.1");
                assert_eq!(config.port, 17000);
                assert_eq!(cli_args.actor, Actors::Verifier);
            })
        })
    }

    #[test]
    fn test_get_cli_config_env_mode() {
        setup_config_env_vars();

        with_env_var("READ_CONFIG_FROM_ENV", Some("1"), || {
            let args = vec!["clementine-core", "operator"];

            let result = get_cli_config_from_args(args);
            assert!(result.is_ok());

            let (config, cli_args) = result.unwrap();
            assert_eq!(config.host, "127.0.0.1");
            assert_eq!(config.port, 17000);
            assert_eq!(cli_args.actor, Actors::Operator);
        });

        cleanup_config_env_vars();
    }

    #[test]
    fn test_get_cli_config_file_without_path() {
        with_env_var("READ_CONFIG_FROM_ENV", Some("0"), || {
            let args = vec!["clementine-core", "verifier"];

            let result = get_cli_config_from_args(args);
            assert!(result.is_err());
        })
    }
}
