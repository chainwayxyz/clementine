//! This module parses CLI arguments and options.

use crate::extended_rpc::{DEFAULT_RPC_PASSWORD, DEFAULT_RPC_URL, DEFAULT_RPC_USER};
use clap::builder::TypedValueParser;
use clap::Parser;
use std::path::PathBuf;

/// Clementine (c) 2024 Chainway Limited
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Remote procedure call URL to communicate with Bitcoin network.
    #[arg(short, long, default_value_t = DEFAULT_RPC_URL.to_string())]
    pub rpc_url: String,
    /// Remote procedure call user name in Bitcoin network. Warning: Not yet implemented.
    #[arg(long, default_value_t = DEFAULT_RPC_USER.to_string())]
    pub rpc_user: String,
    /// Remote procedure call user password in Bitcoin network. Warning: Not yet implemented.
    #[arg(long, default_value_t = DEFAULT_RPC_PASSWORD.to_string())]
    pub rpc_password: String,
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
    pub network: bitcoin::Network,
    /// Private/public key pair file.
    #[arg(short, long)]
    pub key_file: Option<PathBuf>,
}

/// Parse all command line inputs.
pub fn parse_cli() -> Args {
    Args::parse()
}
