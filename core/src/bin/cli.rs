//! This module defines a command line interface for the RPC client.

use clap::{Parser, Subcommand};
use clementine_core::rpc::clementine::{
    clementine_aggregator_client::ClementineAggregatorClient,
    clementine_operator_client::ClementineOperatorClient,
    clementine_verifier_client::ClementineVerifierClient, deposit_params::DepositData, BaseDeposit,
    DepositParams, Empty, Outpoint,
};
use tonic::Request;

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
}

#[derive(Subcommand)]
enum OperatorCommands {
    /// Get deposit keys
    GetDepositKeys {
        #[arg(long)]
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        num_verifiers: u64,
    },
    /// Get operator parameters
    GetParams,
    /// Withdraw funds
    Withdraw {
        #[arg(long)]
        withdrawal_id: u32,
        #[arg(long)]
        input_signature: String,
        #[arg(long)]
        input_outpoint_txid: String,
        #[arg(long)]
        input_outpoint_vout: u32,
        #[arg(long)]
        output_script_pubkey: String,
        #[arg(long)]
        output_amount: u64,
    },
    // Add other operator commands as needed
}

#[derive(Subcommand)]
enum VerifierCommands {
    /// Get verifier parameters
    GetParams,
    /// Generate nonces
    NonceGen {
        #[arg(long)]
        num_nonces: u32,
    },
    /// Set verifier public keys
    SetVerifiers {
        #[arg(long, num_args = 1.., value_delimiter = ',')]
        public_keys: Vec<String>,
    },
    // Add other verifier commands as needed
}

#[derive(Subcommand)]
enum AggregatorCommands {
    /// Setup the system
    Setup,
    /// Process new deposit
    NewDeposit {
        #[arg(long)]
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        evm_address: String,
        #[arg(long)]
        recovery_taproot_address: String,
        #[arg(long)]
        nofn_xonly_pk: String,
        #[arg(long)]
        num_verifiers: u64,
    },
    // Add other aggregator commands as needed
}

async fn handle_operator_call(url: String, command: OperatorCommands) {
    let mut operator = clementine_core::rpc::get_clients(vec![url], |channel| {
        ClementineOperatorClient::new(channel)
    })
    .await
    .expect("Exists")[0]
        .clone();

    match command {
        OperatorCommands::GetDepositKeys {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            num_verifiers,
        } => {
            println!(
                "Getting deposit keys for outpoint {}:{}",
                deposit_outpoint_txid, deposit_outpoint_vout
            );
            let params = clementine_core::rpc::clementine::DepositParams {
                deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                    deposit_outpoint: Some(Outpoint {
                        txid: deposit_outpoint_txid.into(),
                        vout: deposit_outpoint_vout,
                    }),
                    evm_address: vec![1; 20],
                    recovery_taproot_address: String::new(),
                    nofn_xonly_pk: vec![1; 32],
                    num_verifiers,
                })),
            };
            let response = operator
                .get_deposit_keys(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Get deposit keys response: {:?}", response);
        }
        OperatorCommands::GetParams => {
            let params = operator
                .get_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Operator params: {:?}", params);
        }
        OperatorCommands::Withdraw {
            withdrawal_id,
            input_signature,
            input_outpoint_txid,
            input_outpoint_vout,
            output_script_pubkey,
            output_amount,
        } => {
            println!("Processing withdrawal with id {}", withdrawal_id);

            let params = clementine_core::rpc::clementine::WithdrawParams {
                withdrawal_id,
                input_signature: input_signature.as_bytes().to_vec(),
                input_outpoint: Some(Outpoint {
                    txid: input_outpoint_txid.as_bytes().to_vec(),
                    vout: input_outpoint_vout,
                }),
                output_script_pubkey: output_script_pubkey.as_bytes().to_vec(),
                output_amount,
            };
            operator
                .withdraw(Request::new(params))
                .await
                .expect("Failed to make a request");
        }
    }
}

async fn handle_verifier_call(url: String, command: VerifierCommands) {
    println!("Connecting to verifier at {}", url);
    let mut verifier = clementine_core::rpc::get_clients(vec![url], |channel| {
        ClementineVerifierClient::new(channel)
    })
    .await
    .expect("Exists")[0]
        .clone();

    match command {
        VerifierCommands::GetParams => {
            let params = verifier
                .get_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Verifier params: {:?}", params);
        }
        VerifierCommands::NonceGen { num_nonces } => {
            let params = clementine_core::rpc::clementine::NonceGenRequest { num_nonces };
            let response = verifier
                .nonce_gen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Noncegen response: {:?}", response);
        }
        VerifierCommands::SetVerifiers { public_keys } => {
            let params = clementine_core::rpc::clementine::VerifierPublicKeys {
                verifier_public_keys: public_keys.iter().map(|k| k.as_bytes().to_vec()).collect(),
            };
            let response = verifier
                .set_verifiers(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Set verifier public keys response: {:?}", response);
        }
    }
}

async fn handle_aggregator_call(url: String, command: AggregatorCommands) {
    println!("Connecting to aggregator at {}", url);
    let mut aggregator = clementine_core::rpc::get_clients(vec![url], |channel| {
        ClementineAggregatorClient::new(channel)
    })
    .await
    .expect("Exists")[0]
        .clone();

    match command {
        AggregatorCommands::Setup => {
            let setup = aggregator
                .setup(Empty {})
                .await
                .expect("Failed to make a request");
            println!("{:?}", setup);
        }
        AggregatorCommands::NewDeposit {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            evm_address,
            recovery_taproot_address,
            nofn_xonly_pk,
            num_verifiers,
        } => {
            let deposit = aggregator
                .new_deposit(DepositParams {
                    deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                        deposit_outpoint: Some(Outpoint {
                            txid: deposit_outpoint_txid.as_bytes().to_vec(),
                            vout: deposit_outpoint_vout,
                        }),
                        evm_address: evm_address.as_bytes().to_vec(),
                        recovery_taproot_address,
                        nofn_xonly_pk: nofn_xonly_pk.as_bytes().to_vec(),
                        num_verifiers,
                    })),
                })
                .await
                .expect("Failed to make a request");
            println!("{:?}", deposit);
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

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
    }
}
