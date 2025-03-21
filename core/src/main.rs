//! # Clementine 🍊
//!
//! This is Clementine, Citrea's BitVM based trust-minimized two-way peg program.
//!
//! Clementine binary acts as a server for the every actor. An entity should
//! spawn multiple actor servers that it needs, in different processes. Meaning
//! Clementine binary should be run multiple times with different arguments.

use clementine_core::{
    citrea::CitreaClient,
    cli::{self, get_configuration_from_cli},
    database::Database,
    servers::{
        create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    },
};

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
