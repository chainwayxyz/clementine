//! This module defines a command line interface for the RPC client.

use crate::{
    aggregator::{handle_aggregator_call, AggregatorCommands},
    citrea::{handle_citrea_call, CitreaCommands},
    operator::{handle_operator_call, OperatorCommands},
    verifier::{handle_verifier_call, VerifierCommands},
};
use clap::{Parser, Subcommand};
use clementine_core::config::BridgeConfig;
use std::path::PathBuf;

mod aggregator;
mod citrea;
mod operator;
mod utils;
mod verifier;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// URL of the client
    #[arg(short, long)]
    node_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Operator service commands
    Operator {
        #[command(subcommand)]
        command: OperatorCommands,
    },
    /// Verifier service commands
    Verifier {
        #[command(subcommand)]
        command: VerifierCommands,
    },
    /// Aggregator service commands
    Aggregator {
        #[command(subcommand)]
        command: AggregatorCommands,
    },
    /// Citrea related commands
    Citrea {
        #[command(subcommand)]
        command: CitreaCommands,
    },
}

// Create a minimal config with default TLS paths
fn create_minimal_config() -> BridgeConfig {
    BridgeConfig {
        server_cert_path: PathBuf::from("core/certs/server/server.pem"),
        server_key_path: PathBuf::from("core/certs/server/server.key"),
        ca_cert_path: PathBuf::from("core/certs/ca/ca.pem"),
        client_cert_path: PathBuf::from("core/certs/client/client.pem"),
        client_key_path: PathBuf::from("core/certs/client/client.key"),
        client_verification: true,
        ..Default::default()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if !std::path::Path::new("core/certs/ca/ca.pem").exists() {
        println!("sss {:?}", std::env::current_dir());

        if PathBuf::from(
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"),
        )
        .canonicalize()
        .expect("Failed to canonicalize path")
            != std::env::current_dir().expect("Failed to get current directory")
        {
            println!("Error: CA certificates not found in expected path, please run this command from the `core` directory. Current directory: {}", std::env::current_dir().expect("Failed to get current directory").to_str().expect("Failed to get current directory as string"));
        } else {
            println!("Error: CA certificates not found in expected path, please generate them before running the CLI");
        }
        return;
    }

    match cli.command {
        Commands::Operator { command } => {
            handle_operator_call(cli.node_url, command).await;
        }
        Commands::Verifier { command } => {
            handle_verifier_call(cli.node_url, command).await;
        }
        Commands::Aggregator { command } => {
            handle_aggregator_call(cli.node_url, command).await;
        }
        Commands::Citrea { command } => {
            handle_citrea_call(cli.node_url, command).await;
        }
    }
}
