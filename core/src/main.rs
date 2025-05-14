//! # Clementine 🍊
//!
//! This is Clementine, Citrea's BitVM based trust-minimized two-way peg program.
//!
//! Clementine binary acts as a server for the every actor. An entity should
//! spawn multiple actor servers that it needs, in different processes. Meaning
//! Clementine binary should be run multiple times with different arguments.

use clementine_core::{
    citrea::CitreaClient,
    cli::{self, get_cli_config},
    database::Database,
    servers::{
        create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    },
};

#[tokio::main]
async fn main() {
    let (config, args) = get_cli_config();

    Database::run_schema_script(&config, args.actor == cli::Actors::Verifier)
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

            let result = create_aggregator_grpc_server(config.clone()).await;

            match result {
                Ok(server) => server.1,
                Err(e) => {
                    eprintln!("Error creating aggregator server: {}", e);
                    eprintln!("Error creating aggregator server: {:?}", e);
                    println!("Error creating aggregator server: {}", e);
                    println!("Error creating aggregator server: {:?}", e);
                    tracing::error!("Error creating aggregator server: {}", e);
                    tracing::error!("Error creating aggregator server: {}", e.to_string());
                    tracing::error!("Error creating aggregator server: {:?}", e);
                    return;
                }
            }
        }
    };
    println!("Server has started successfully.");

    handle.closed().await;
}
