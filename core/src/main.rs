//! # Clementine 🍊
//!
//! This is Clementine, Citrea's BitVM based trust-minimized two-way peg program.
//!
//! Clementine binary acts as a server for the every actor. An entity should
//! spawn multiple actor servers that it needs, in different processes. Meaning
//! Clementine binary should be run multiple times with different arguments.

use clementine_core::{
    citrea::CitreaClient,
    cli::{self, Args},
    config::BridgeConfig,
    database::Database,
    servers::{
        create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    },
};
use std::{process::exit, str::FromStr};
use tracing::{level_filters::LevelFilter, Level};

/// Gets configuration from CLI. If there are any errors, print error to stderr
/// and exit program.
///
/// Steps:
///
/// 1. Get CLI arguments
/// 2. Initialize logger
/// 3. Get configuration file
///
/// # Returns
///
/// A tuple, containing:
///
/// - [`BridgeConfig`] from CLI argument
/// - [`Args`] from CLI options
pub fn get_configuration_from_cli() -> (BridgeConfig, Args) {
    let args = match clementine_core::cli::parse() {
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

    match clementine_core::utils::initialize_logger(level_filter) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };
    let config = match clementine_core::cli::get_configuration_from(args.clone()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };

    (config, args)
}

#[tokio::main]
async fn main() {
    let (config, args) = get_configuration_from_cli();

    Database::run_schema_script(&config)
        .await
        .expect("Can't run schema script");

    let mut handle = match args.actor {
        cli::Actors::Verifier => {
            println!("Starting verifier server...");

            create_verifier_grpc_server::<CitreaClient>(config.clone())
                .await
                .expect("Can't create verifier server")
                .1
        }
        cli::Actors::Operator => {
            println!("Starting operator server...");

            create_operator_grpc_server::<CitreaClient>(config.clone())
                .await
                .expect("Can't create operator server")
                .1
        }
        cli::Actors::Aggregator => {
            println!("Starting aggregator server...");

            create_aggregator_grpc_server(config.clone())
                .await
                .expect("Can't create aggregator server")
                .1
        }
    };
    println!("Server has started successfully.");

    handle.closed().await;
}
