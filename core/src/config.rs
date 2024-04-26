//! # Configuration Options for Clementine
//!
//! This module handles cli arguments, cli options and environment variables to
//! generate a config struct for the rest of the program.
//!
//! ## Flow
//!
//! 1. Run clap to collect cli arguments/options
//! 2. Parse arguments/options using Clap
//! 3. If arguments/options are not complete, return with an error
//! 4. Construct a `BridgeConfig`
//! 5. Return `BridgeConfig`

use crate::errors::BridgeError;
use bitcoin::Network;
use bitcoincore_rpc::Auth;
use clap::builder::TypedValueParser;
use clap::Parser;
use std::ffi::OsString;
use std::{env, fs};

/// Clementine (C) 2024 Chainway Limited
///
/// ^
/// |_ This is for the help message (`--help`), please leave it as is.
///
/// This struct can both be used to parse cli arguments/options using `Clap`
/// and pass information to other parts of the program. Some of the arguments
/// can be skipped for parsing and can only be used for data passing inside the
/// program. Please check below code and documentation of the `Clap` for
/// examples.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct BridgeConfig {
    /// File path for the mock database.
    #[arg(long)]
    pub db_file_path: String,

    /// Number of verifiers.
    #[arg(long)]
    pub num_verifiers: usize,

    /// Minimum relay fee.
    #[arg(long)]
    pub min_relay_fee: u64,

    /// User takes after.
    #[arg(long)]
    pub user_takes_after: u32,

    /// Threshold for confirmation.
    #[arg(long)]
    pub confirmation_treshold: u32,

    /// Bitcoin network to work on.
    #[arg(
        short,
        long,
        default_value_t = bitcoin::Network::Regtest,
        value_parser = clap::builder::PossibleValuesParser
            ::new(["bitcoin", "testnet", "signet", "regtest"])
            .map(|s| s.parse::<bitcoin::Network>().unwrap()),
        )
    ]
    pub network: Network,

    /// Bitcoin remote procedure call URL.
    #[arg(long)]
    pub bitcoin_rpc_url: String,

    /// Bitcoin remote procedure call user name.
    #[arg(long)]
    pub bitcoin_rpc_user: String,

    /// Bitcoin remote procedure call user password.
    #[arg(long)]
    pub bitcoin_rpc_password: String,

    /// Bitcoin RPC user authorization.
    #[clap(skip=Auth::None)]
    pub bitcoin_rpc_auth: Auth,
}

impl BridgeConfig {
    pub fn new() -> Result<Self, BridgeError> {
        let args = env::args();

        match BridgeConfig::new_from_iter(env::args()) {
            Ok(c) => Ok(c),
            Err(e) => match BridgeConfig::parse_from_file(args) {
                Ok(c) => Ok(c),
                Err(_) => Err(e),
            },
        }
    }

    /// Parses cli arguments from given iterator.
    fn new_from_iter<I, T>(itr: I) -> Result<Self, BridgeError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        match BridgeConfig::try_parse_from(itr) {
            Ok(c) => Ok(c),
            Err(e) => Err(BridgeError::ConfigError(e.to_string())),
        }
    }

    /// Beware ugly code ahead!
    ///
    /// This thing checks if a file is given as input for the cli
    /// arguments. If there are any error with the input file, we
    /// fallback to standard cli parsing. Program must be run in this
    /// format:
    ///
    /// $ clementine-core $ARGFILE
    ///
    /// Why do we do this? We wanted to read program options from a file
    /// but did not wanted to write duplicate code for every new option.
    /// So I did came up with this monstrosity as the solution. Sorry, world.
    fn parse_from_file<I, T>(itr: I) -> Result<Self, BridgeError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut it = itr.into_iter();

        if let Some(_program_name) = it.next() {
            if let Some(input_file) = it.next() {
                if let Ok(contents) = fs::read_to_string(input_file.into()) {
                    if let Ok(c) = BridgeConfig::new_from_iter(contents.split(" ")) {
                        return Ok(c);
                    };
                }
            }
        };

        Err(BridgeError::ConfigError("Input file is not OK".to_string()))
    }

    /// TODO: This should only be compiled when program is configured as `test`.
    /// When this is possible, uncomment below.
    // #[cfg(test)]
    pub fn test_config() -> Self {
        BridgeConfig::default()
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            db_file_path: "database".to_string(),
            num_verifiers: 4,
            min_relay_fee: 289,
            user_takes_after: 200,
            confirmation_treshold: 1,
            network: Network::Regtest,
            bitcoin_rpc_url: "http://localhost:18443".to_string(),
            bitcoin_rpc_user: "admin".to_string(),
            bitcoin_rpc_password: "admin".to_string(),
            bitcoin_rpc_auth: Auth::UserPass("admin".to_string(), "admin".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BridgeConfig;
    use crate::errors::BridgeError;
    use std::fs::File;
    use std::io::Write;

    /// Without any arguments given, a `BridgeError` should be received.
    #[test]
    fn no_arguments() {
        match BridgeConfig::new_from_iter(vec![""].into_iter()) {
            Ok(c) => {
                println!("{:#?}", c);
                assert!(true);
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

    /// With help message flag, we should see the help message. Shocking.
    #[test]
    fn help_message() {
        match BridgeConfig::new_from_iter(vec!["clementine-core", "--help"].into_iter()) {
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
        match BridgeConfig::new_from_iter(vec!["clementine-core", "--version"].into_iter()) {
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

    /// Args file can be used to specify arguments.
    #[test]
    fn args_file() {
        const FILE_NAME: &str = "conffile";
        const FILE_CONTENTS: &str = "--db-file-path database
        --num-verifiers 4
        --min-relay-fee 289
        --user-takes-after 200
        --confirmation-treshold 1
        --bitcoin-rpc-url http://localhost:18443
        --bitcoin-rpc-user admin
        --bitcoin-rpc-password admin
        ";

        let mut file = File::create(FILE_NAME).unwrap();
        file.write_all(FILE_CONTENTS.as_bytes()).unwrap();

        match BridgeConfig::parse_from_file(vec!["clementine-core", FILE_NAME].into_iter()) {
            Ok(c) => {
                println!("{:#?}", c);
                assert!(true);
            }
            Err(BridgeError::ConfigError(_)) => {
                assert!(false);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
}
