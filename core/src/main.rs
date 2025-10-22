//! # Clementine 🍊
//!
//! This is Clementine, Citrea's BitVM based trust-minimized two-way peg program.
//!
//! Clementine binary acts as a server for the every actor. An entity should
//! spawn multiple actor servers that it needs, in different processes. Meaning
//! Clementine binary should be run multiple times with different arguments.

use bitcoincore_rpc::RpcApi;
use clementine_core::{
    actor::Actor,
    bitvm_client::{load_or_generate_bitvm_cache, BITVM_CACHE},
    citrea::CitreaClient,
    cli::{self, get_cli_config},
    database::Database,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    servers::{
        create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    },
    utils::{initialize_logger, initialize_telemetry},
};
use std::str::FromStr;
use tracing::{level_filters::LevelFilter, Level};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let (config, args) = get_cli_config();

    let level_filter = match args.verbose {
        0 => None,
        other => Some(LevelFilter::from_level(
            Level::from_str(&other.to_string()).unwrap_or(Level::INFO),
        )),
    };

    initialize_logger(level_filter).expect("Failed to initialize logger.");

    if let Some(telemetry) = &config.telemetry {
        if let Err(e) = initialize_telemetry(telemetry) {
            tracing::error!("Failed to initialize telemetry listener: {:?}", e);
        }
    }

    config
        .check_general_requirements()
        .await
        .expect("Configuration is invalid");

    // Load the BitVM cache on startup.
    tracing::info!("Loading BitVM cache...");
    BITVM_CACHE.get_or_init(load_or_generate_bitvm_cache);

    Database::run_schema_script(&config, args.actor == cli::Actors::Verifier)
        .await
        .expect("Can't run schema script");

    let mut handle = match args.actor {
        cli::Actors::Verifier => {
            println!("Starting verifier server...");
            config
                .check_mainnet_requirements(cli::Actors::Verifier)
                .expect("Illegal configuration options!");

            create_verifier_grpc_server::<CitreaClient>(config.clone())
                .await
                .expect("Can't create verifier server")
                .1
        }
        cli::Actors::Operator => {
            println!("Starting operator server...");
            config
                .check_mainnet_requirements(cli::Actors::Operator)
                .expect("Illegal configuration options!");

            create_operator_grpc_server::<CitreaClient>(config.clone())
                .await
                .expect("Can't create operator server")
                .1
        }
        cli::Actors::Aggregator => {
            println!("Starting aggregator server...");
            config
                .check_mainnet_requirements(cli::Actors::Aggregator)
                .expect("Illegal configuration options!");

            create_aggregator_grpc_server(config.clone())
                .await
                .expect("Can't create aggregator server")
                .1
        }
        cli::Actors::TestActor => {
            let rpc = ExtendedBitcoinRpc::connect(
                config.bitcoin_rpc_url.clone(),
                config.bitcoin_rpc_user.clone(),
                config.bitcoin_rpc_password.clone(),
                None,
            )
            .await
            .expect("Failed to connect to Bitcoin RPC");

            // Test DB connection with running the schema script.
            Database::run_schema_script(&config, true)
                .await
                .expect("Database connection failed");

            // This also checks if Bitcoin connection is healthy or not.
            let unspents = rpc
                .list_unspent(None, None, None, None, None)
                .await
                .expect("Failed to get unspent outputs");
            let mut addresses = vec![];
            for unspent in unspents {
                if let Some(address) = unspent.address {
                    let serialized_address = address.assume_checked().to_string();

                    if !addresses.contains(&serialized_address) {
                        addresses.push(serialized_address);
                    }
                }
            }
            let address = Actor::new(config.secret_key, config.protocol_paramset.network).address;

            println!("Configuration: {config:#?}");
            println!("Bitcoin address: {address}");
            println!("Bitcoin node addresses: {addresses:?}");

            println!("DB connection is successful.");
            println!("Bitcoin node connection is successful.");
            println!("Your node is healthy and ready to run.");

            std::process::exit(0);
        }
    };
    println!("Server has started successfully.");

    handle.closed().await;
}
