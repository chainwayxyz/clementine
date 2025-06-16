//! This module defines a command line interface for the RPC client.

use bitcoin::{hashes::Hash, secp256k1::schnorr, ScriptBuf};
use bitcoincore_rpc::RpcApi;
use clap::{Parser, Subcommand};
use clementine_core::{
    citrea::{CitreaClient, CitreaClientT},
    config::BridgeConfig,
    deposit::SecurityCouncil,
    extended_rpc,
    rpc::clementine::{
        self, clementine_aggregator_client::ClementineAggregatorClient,
        clementine_operator_client::ClementineOperatorClient,
        clementine_verifier_client::ClementineVerifierClient, deposit::DepositData, Actors,
        BaseDeposit, Deposit, Empty, Outpoint, ReplacementDeposit, SendMoveTxRequest,
    },
    utils::{bitcoin_merkle::get_block_merkle_proof, citrea::get_transaction_params_for_citrea},
    EVMAddress, UTXO,
};
use std::path::PathBuf;
use std::str::FromStr;
use tonic::Request;

mod aggregator;
mod citrea;
mod operator;
mod verifier;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The URL of the gRPC service
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
        server_cert_path: PathBuf::from("certs/server/server.pem"),
        server_key_path: PathBuf::from("certs/server/server.key"),
        ca_cert_path: PathBuf::from("certs/ca/ca.pem"),
        client_cert_path: PathBuf::from("certs/client/client.pem"),
        client_key_path: PathBuf::from("certs/client/client.key"),
        client_verification: true,
        ..Default::default()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if !std::path::Path::new("certs/ca/ca.pem").exists() {
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
