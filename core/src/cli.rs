//! # Command Line Interface
//!
//! This module defines command line interface for binaries. `Clap` is used
//! for easy generation of help messages and handling arguments.

use crate::config::protocol::ProtocolParamsetName;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::errors::ErrorExt;
use crate::utils;
use crate::utils::delayed_panic;
use clap::Parser;
use clap::ValueEnum;
use eyre::Context;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;
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

/// Parse all the command line arguments and generate a `BridgeConfig`.
fn parse_args() -> Result<Args, BridgeError> {
    parse_from(env::args())
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

/// Reads configuration file, parses it and generates a `BridgeConfig` from
/// given cli arguments.
fn read_config_from(config_file: PathBuf) -> Result<BridgeConfig, BridgeError> {
    match BridgeConfig::try_parse_file(config_file) {
        Ok(c) => Ok(c),
        Err(e) => Err(BridgeError::ConfigError(e.to_string())),
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConfigSource {
    File(PathBuf),
    Env,
}

pub fn get_config_source(
    env_name: &'static str,
    provided_arg: Option<PathBuf>,
) -> Result<ConfigSource, BridgeError> {
    Ok(match std::env::var(env_name) {
        Err(_) => ConfigSource::File(provided_arg.ok_or(BridgeError::ConfigError(
            "No file path or environment variable provided for config file.".to_string(),
        ))?),
        Ok(str) if str == "0" || str == "off" => ConfigSource::File(provided_arg.ok_or(
            BridgeError::ConfigError("No file path provided for config file.".to_string()),
        )?),
        Ok(str) => {
            if str != "1" || str != "on" {
                tracing::warn!("Unknown value for {env_name}: {str}. Expected 1/0/off/on. Defaulting to environment variables.");
            }

            if provided_arg.is_some() {
                tracing::warn!("File path provided in CLI arguments while {env_name} is set to 1. Ignoring provided file path and reading from environment variables.");
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
/// 3. Get configuration file, either from environment variables or
///    configuration file
///
/// # Returns
///
/// A tuple, containing:
///
/// - [`BridgeConfig`] from CLI argument
/// - [`Args`] from CLI options
pub fn get_configuration_from_cli() -> (BridgeConfig, Args) {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };

    let level_filter = match args.verbose {
        0 => None,
        other => Some(LevelFilter::from_level(
            Level::from_str(&other.to_string()).unwrap_or(Level::INFO),
        )),
    };

    match utils::initialize_logger(level_filter) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };

    let protocol_params_source =
        get_config_source("READ_PARAMSET_FROM_ENV", args.protocol_params_file.clone())
            .wrap_err("Failed to determine source for protocol parameters.");

    let paramset = match protocol_params_source {
        Err(e) => {
            tracing::error!("Failed to determine source for protocol parameters: {e:?}");
            delayed_panic!("Failed to determine source for protocol parameters: {e:?}");
        }
        Ok(ConfigSource::File(path)) => {
            // TODO: Temporary solution, make it better
            std::env::set_var("PROTOCOL_CONFIG_PATH", path.to_str().unwrap_or_default());
            ProtocolParamsetName::File
        }
        Ok(ConfigSource::Env) => ProtocolParamsetName::Env,
    };

    let config_source = get_config_source("READ_CONFIG_FROM_ENV", args.config_file.clone())
        .wrap_err("Failed to determine source for configuration.");

    let (mut config, args) = match config_source {
        Err(e) => {
            tracing::error!("Failed to determine source for configuration: {e:?}");
            delayed_panic!("Failed to determine source for configuration: {e:?}");
        }
        Ok(ConfigSource::File(config_file)) => {
            // Read from configuration file ONLY
            let config = match read_config_from(config_file) {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!("Can't read configuration from file: {e:?}");
                    delayed_panic!("Can't read configuration from file: {e:?}");
                }
            };

            (config, args)
        }
        Ok(ConfigSource::Env) => {
            match BridgeConfig::from_env() {
                Ok(config) => (config, args),
                Err(e) => {
                    // Handle the root cause
                    let e = e.into_eyre();
                    match e.root_cause().downcast_ref::<BridgeError>() {
                        Some(BridgeError::EnvVarNotSet(e, field)) => {
                            tracing::error!(
                                "Missing environment variable {field} in environment config mode. ({e:?})."
                            );
                            delayed_panic!("Missing environment variable {field} in environment config mode. ({e:?}).");
                        }
                        Some(BridgeError::EnvVarMalformed(e, field)) => {
                            tracing::error!("Malformed environment variable {field} in environment config mode. ({e:?}).");
                            delayed_panic!("Malformed environment variable {field} in environment config mode. ({e:?}).");
                        }
                        _ => {
                            tracing::error!(
                            "Error occurred while reading environment variables for config: {e:?}"
                            );
                            delayed_panic!("Error occurred while reading environment variables for config: {e:?}. ({e:?}).");
                        }
                    }
                }
            }
        }
    };

    config.protocol_paramset = paramset;

    (config, args)
}

#[cfg(test)]
mod tests {
    use super::parse_from;
    use crate::errors::BridgeError;

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
}
