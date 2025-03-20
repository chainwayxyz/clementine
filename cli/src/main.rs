use clap::{Parser, Subcommand};
use clementine_core::rpc::clementine::{
    BaseDeposit, DepositParams, Empty, Outpoint,
    clementine_aggregator_client::ClementineAggregatorClient,
    clementine_operator_client::ClementineOperatorClient, deposit_params::DepositData,
};

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
    },
    // Add other aggregator commands as needed
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Here you would implement the actual gRPC client calls based on the parsed commands
    match cli.command {
        Commands::Operator { command } => {
            let mut operator = clementine_core::rpc::get_clients(vec![cli.node_url], |channel| {
                ClementineOperatorClient::new(channel)
            })
            .await
            .unwrap()[0]
                .clone();
            match command {
                OperatorCommands::GetDepositKeys {
                    deposit_outpoint_txid,
                    deposit_outpoint_vout,
                } => {
                    println!(
                        "Getting deposit keys for outpoint {}:{}",
                        deposit_outpoint_txid, deposit_outpoint_vout
                    );
                }
                OperatorCommands::GetParams => {
                    let params = operator.get_params(Empty {}).await.unwrap();
                    println!("{:?}", params);
                }
                OperatorCommands::Withdraw {
                    withdrawal_id,
                    input_signature,
                    input_outpoint_txid,
                    input_outpoint_vout,
                    output_script_pubkey,
                    output_amount,
                } => {
                    println!("Processing withdrawal {}", withdrawal_id);
                }
            }
        }
        Commands::Verifier { command } => {
            println!("Connecting to verifier at {}", cli.node_url);
            match command {
                VerifierCommands::GetParams => {
                    println!("Getting verifier parameters");
                }
                VerifierCommands::NonceGen { num_nonces } => {
                    println!("Generating {} nonces", num_nonces);
                }
                VerifierCommands::SetVerifiers { public_keys } => {
                    println!("Setting verifier public keys: {:?}", public_keys);
                }
            }
        }
        Commands::Aggregator { command } => {
            println!("Connecting to aggregator at {}", cli.node_url);
            let mut aggregator = clementine_core::rpc::get_clients(vec![cli.node_url], |channel| {
                ClementineAggregatorClient::new(channel)
            })
            .await
            .unwrap()[0]
                .clone();
            match command {
                AggregatorCommands::Setup => {
                    let setup = aggregator.setup(Empty {}).await.unwrap();
                    println!("{:?}", setup);
                }
                AggregatorCommands::NewDeposit {
                    deposit_outpoint_txid,
                    deposit_outpoint_vout,
                    evm_address,
                    recovery_taproot_address,
                    nofn_xonly_pk,
                } => {
                    println!(
                        "Processing new deposit for outpoint {}:{}",
                        deposit_outpoint_txid, deposit_outpoint_vout
                    );
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
                            })),
                        })
                        .await
                        .unwrap();
                    println!("{:?}", deposit);
                }
            }
        }
    }
}
