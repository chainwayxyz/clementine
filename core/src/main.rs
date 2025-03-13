//! # Clementine 🍊
//!
//! This is Clementine, Citrea's BitVM based trust-minimized two-way peg program.
//!
//! Clementine binary acts as a server for the every actor. An entity should
//! spawn multiple actor servers that it needs, in different processes. Meaning
//! Clementine binary should be run multiple times with different arguments.

use database::Database;
use servers::{
    create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    create_watchtower_grpc_server,
};
use utils::get_configuration_for_binaries;

pub mod actor;
pub mod aggregator;
pub mod bitcoin_syncer;
pub mod bitvm_client;
pub mod builder;
pub mod citrea;
pub mod cli;
pub mod config;
pub mod constants;
pub mod database;
pub mod errors;
pub mod extended_rpc;
pub mod header_chain_prover;
pub mod musig2;
pub mod operator;
pub mod rpc;
pub mod servers;
pub mod states;
pub mod task;
pub mod tx_sender;
pub mod utils;
pub mod verifier;
pub mod watchtower;

#[cfg(test)]
pub mod test;

#[tokio::main]
async fn main() {
    let (config, args) = get_configuration_for_binaries();

    Database::run_schema_script(&config)
        .await
        .expect("Can't run schema script");

    let mut handle = match args.actor {
        cli::Actors::Verifier => {
            println!("Starting verifier server...");

            create_verifier_grpc_server(config.clone())
                .await
                .expect("Can't create verifier server")
                .1
        }
        cli::Actors::Operator => {
            println!("Starting operator server...");

            create_operator_grpc_server(config.clone())
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
        cli::Actors::Watchtower => {
            println!("Starting watchtower server...");

            create_watchtower_grpc_server(config.clone())
                .await
                .expect("Can't create watchtower server")
                .1
        }
    };
    println!("Server has started successfully.");

    handle.closed().await;
}
