use database::Database;
use servers::{
    create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    create_watchtower_grpc_server,
};
use std::process::exit;
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
pub mod tx_sender;
pub mod utils;
pub mod verifier;
pub mod watchtower;

#[cfg(test)]
pub mod test;

#[tokio::main]
async fn main() {
    eprintln!("\nBEWARE: Current behavior of this binary might be incorrect! It is in active development.\n");

    let (mut config, args) = get_configuration_for_binaries();

    if !args.verifier_server
        && !args.operator_server
        && !args.aggregator_server
        && !args.watchtower_server
    {
        eprintln!("No servers are specified. Please specify one.");
        exit(1);
    }

    Database::run_schema_script(&config)
        .await
        .expect("Can't run schema script");

    let mut handles = vec![];

    if args.verifier_server {
        handles.push(
            create_verifier_grpc_server(config.clone())
                .await
                .expect("Can't create verifier server")
                .1,
        );
        config.port += 1;

        println!("Verifier server is started.");
    }

    if args.operator_server {
        handles.push(
            create_operator_grpc_server(config.clone())
                .await
                .expect("Can't create operator server")
                .1,
        );
        config.port += 1;

        println!("Operator server is started.");
    }

    if args.aggregator_server {
        handles.push(
            create_aggregator_grpc_server(config.clone())
                .await
                .expect("Can't create aggregator server")
                .1,
        );
        config.port += 1;

        println!("Aggregator server is started.");
    }

    if args.watchtower_server {
        handles.push(
            create_watchtower_grpc_server(config)
                .await
                .expect("Can't create watchtower server")
                .1,
        );

        println!("Watchtower server is started.");
    }

    // Wait for servers to close, A.K.A. run forever.
    for mut handle in handles {
        handle.closed().await;
    }
}
