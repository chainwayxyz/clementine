//! # Command Line Interface
//!
//! This module defines command line interface for binaries. `Clap` is used
//! for easy generation of help messages and handling arguments.

use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::utils;
use clap::Parser;
use clap::ValueEnum;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use tracing::level_filters::LevelFilter;
use tracing::Level;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Actors {
    Verifier,
    Operator,
    Aggregator,
    Watchtower,
}

/// Clementine (C) 2025 Chainway Limited
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Actor to run.
    pub actor: Actors,
    /// TOML formatted configuration file.
    pub config_file: Option<PathBuf>,
    /// Verbosity level, ranging from 0 (none) to 5 (highest)
    #[arg(short, long, default_value_t = 3)]
    pub verbose: u8,
}

/// Parse all the command line arguments and generate a `BridgeConfig`.
fn parse() -> Result<Args, BridgeError> {
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
fn get_configuration_from(config_file: PathBuf) -> Result<BridgeConfig, BridgeError> {
    match BridgeConfig::try_parse_file(config_file) {
        Ok(c) => Ok(c),
        Err(e) => Err(BridgeError::ConfigError(e.to_string())),
    }
}

/// Gets configuration from CLI, for binaries. If there are any errors, prints
/// error and exits the program.
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
    let args = match parse() {
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

    // Return early if environment variables are set.
    match BridgeConfig::from_env() {
        Ok(config) => {
            tracing::info!(
                "All the environment variables are set. Using them instead of configuration file..."
            );

            return (config, args);
        }
        Err(BridgeError::EnvVarNotSet(_)) => {
            tracing::info!("Not all the config overwrite environment variables are set, using configuration file...");
        }
        Err(e) => {
            // TODO: Almost every error is converted automatically and it's not
            // possible to tell which env var is malformed without managing
            // every error manually. Maybe the new error interface will solve
            // this problem?
            tracing::error!("Malformed value set to an environment variable: {e}");
            exit(1);
        }
    }

    let config_file = if let Some(config_file) = args.config_file.clone() {
        config_file
    } else {
        tracing::error!(
            "Neither environment variables are set nor a configuration file is provided!"
        );
        exit(1);
    };

    let config = match get_configuration_from(config_file) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("Can't read configuration file: {e}");
            exit(1);
        }
    };

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
