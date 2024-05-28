//! # Command Line Interface
//!
//! This module defines command line interface for binaries. `Clap` is used
//! for easy generation of help messages and handling arguments.

use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use clap::Parser;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;

/// Clementine (C) 2024 Chainway Limited
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// TOML formatted configuration file.
    pub config_file: PathBuf,
}

/// Parse all the cli arguments and generate a `BridgeConfig`.
pub fn parse() -> Result<Args, BridgeError> {
    parse_from(env::args())
}

/// Parse given iterator. This is good for isolated environments, like tests.
pub fn parse_from<I, T>(itr: I) -> Result<Args, BridgeError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Args::try_parse_from(itr) {
        Ok(c) => Ok(c),
        Err(e) => Err(BridgeError::ConfigError(e.to_string())),
    }
}

/// Parses cli arguments, reads configuration file, parses it and generates a
/// `BridgeConfig`.
///
/// # Kills Process
///
/// Prints help + error messages and kills process on error. This will not panic
/// intentionally, just to print a user friendly message and not a trace.
pub fn get_configuration() -> BridgeConfig {
    let args = match parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e.to_string());
            exit(1);
        }
    };

    match get_configuration_from(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e.to_string());
            exit(1);
        }
    }
}

/// Reads configuration file, parses it and generates a `BridgeConfig` from
/// given cli arguments.
pub fn get_configuration_from(args: Args) -> Result<BridgeConfig, BridgeError> {
    match BridgeConfig::try_parse_file(args.config_file) {
        Ok(c) => Ok(c),
        Err(e) => Err(BridgeError::ConfigError(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_from;
    use crate::errors::BridgeError;

    /// With help message flag, we should see the help message. Shocking.
    #[test]
    fn help_message() {
        match parse_from(vec!["clementine-core", "--help"].into_iter()) {
            Ok(_) => {
                assert!(false);
            }
            Err(BridgeError::ConfigError(e)) => {
                println!("{}", e);
                assert!(true);
            }
            _ => {
                assert!(false);
            }
        }
    }

    /// With version flag, we should see the program version read from
    /// `Cargo.toml`.
    #[test]
    fn version() {
        match parse_from(vec!["clementine-core", "--version"].into_iter()) {
            Ok(_) => {
                assert!(false);
            }
            Err(BridgeError::ConfigError(e)) => {
                println!("{}", e);
                assert!(true);
            }
            _ => {
                assert!(false);
            }
        }
    }
}
