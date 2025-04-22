//! This module defines a command line interface for the RPC client.

use std::str::FromStr;

use bitcoin::{hashes::Hash, Amount};
use clap::{Parser, Subcommand};
use clementine_core::{
    rpc::clementine::{
        clementine_aggregator_client::ClementineAggregatorClient,
        clementine_operator_client::ClementineOperatorClient,
        clementine_verifier_client::ClementineVerifierClient, deposit::DepositData, Actors,
        BaseDeposit, Deposit, Empty, Outpoint, VerifierPublicKeys, XOnlyPublicKeys,
    },
    EVMAddress,
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
    // /// Set verifier public keys
    // SetVerifiers {
    //     #[arg(long, num_args = 1.., value_delimiter = ',')]
    //     public_keys: Vec<String>,
    // },
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
        evm_address: Option<String>,
        #[arg(long)]
        recovery_taproot_address: Option<String>,
    },
    /// Get the aggregated NofN x-only public key
    GetNofnAggregatedKey,
    /// Get deposit address
    GetDepositAddress {
        #[arg(long)]
        evm_address: Option<String>,
        #[arg(long)]
        recovery_taproot_address: Option<String>,
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        bridge_amount: Option<u64>,
        #[arg(long)]
        user_takes_after: Option<u64>,
    },
    /// Get transaction parameters of a move transaction
    GetTxParamsOfMoveTx {
        #[arg(long)]
        move_txid: String,
    },
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
        } => {
            println!(
                "Getting deposit keys for outpoint {}:{}",
                deposit_outpoint_txid, deposit_outpoint_vout
            );
            let params = clementine_core::rpc::clementine::DepositParams {
                deposit: Some(Deposit {
                    deposit_outpoint: Some(Outpoint {
                        txid: deposit_outpoint_txid.into(),
                        vout: deposit_outpoint_vout,
                    }),
                    deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                        evm_address: vec![1; 20],
                        recovery_taproot_address: String::new(),
                    })),
                }),
                actors: Some(Actors {
                    verifiers: Some(VerifierPublicKeys {
                        verifier_public_keys: vec![],
                    }),
                    watchtowers: Some(XOnlyPublicKeys {
                        xonly_public_keys: vec![],
                    }),
                    operators: Some(XOnlyPublicKeys {
                        xonly_public_keys: vec![],
                    }),
                }),
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
        } => {
            let evm_address = match evm_address {
                Some(address) => EVMAddress(
                    hex::decode(address)
                        .expect("Failed to decode evm address")
                        .try_into()
                        .expect("Failed to convert evm address to array"),
                ),
                None => EVMAddress([1; 20]),
            };

            let recovery_taproot_address = match recovery_taproot_address {
                Some(address) => bitcoin::Address::from_str(&address)
                    .expect("Failed to parse recovery taproot address"),
                None => bitcoin::Address::from_str(
                    "tb1p9k6y4my6vacczcyc4ph2m5q96hnxt5qlrqd9484qd9cwgrasc54qw56tuh",
                )
                .expect("Failed to parse recovery taproot address"),
            };

            let mut deposit_outpoint_txid =
                hex::decode(deposit_outpoint_txid).expect("Failed to decode txid");
            deposit_outpoint_txid.reverse();

            let deposit = aggregator
                .new_deposit(Deposit {
                    deposit_outpoint: Some(Outpoint {
                        txid: deposit_outpoint_txid,
                        vout: deposit_outpoint_vout,
                    }),
                    deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                        evm_address: evm_address.0.to_vec(),
                        recovery_taproot_address: recovery_taproot_address
                            .assume_checked()
                            .to_string(),
                    })),
                })
                .await
                .expect("Failed to make a request");
            let move_txid = deposit.get_ref().txid.clone();
            let txid = bitcoin::Txid::from_byte_array(
                move_txid
                    .try_into()
                    .expect("Failed to convert txid to array"),
            );
            println!("Move txid: {}", txid);
        }
        AggregatorCommands::GetNofnAggregatedKey => {
            let response = aggregator
                .get_nofn_aggregated_xonly_pk(Request::new(Empty {}))
                .await
                .expect("Failed to make a request");
            let xonly_pk = bitcoin::XOnlyPublicKey::from_slice(&response.get_ref().nofn_xonly_pk)
                .expect("Failed to parse xonly_pk");
            println!("{:?}", xonly_pk.to_string());
        }
        AggregatorCommands::GetDepositAddress {
            evm_address,
            recovery_taproot_address,
            network,
            bridge_amount,
            user_takes_after,
        } => {
            let response = aggregator
                .get_nofn_aggregated_xonly_pk(Request::new(Empty {}))
                .await
                .expect("Failed to make a request");
            let xonly_pk = bitcoin::XOnlyPublicKey::from_slice(&response.get_ref().nofn_xonly_pk)
                .expect("Failed to parse xonly_pk");

            let recovery_taproot_address = match recovery_taproot_address {
                Some(address) => bitcoin::Address::from_str(&address)
                    .expect("Failed to parse recovery taproot address"),
                None => bitcoin::Address::from_str(
                    "tb1p9k6y4my6vacczcyc4ph2m5q96hnxt5qlrqd9484qd9cwgrasc54qw56tuh",
                )
                .expect("Failed to parse recovery taproot address"),
            };

            let evm_address = match evm_address {
                Some(address) => EVMAddress(
                    hex::decode(address)
                        .expect("Failed to decode evm address")
                        .try_into()
                        .expect("Failed to convert evm address to array"),
                ),
                None => EVMAddress([1; 20]),
            };

            let network = match network {
                Some(network) => {
                    bitcoin::Network::from_str(&network).expect("Failed to parse network")
                }
                None => bitcoin::Network::Regtest,
            };

            let bridge_amount = match bridge_amount {
                Some(amount) => Amount::from_sat(amount),
                None => Amount::from_sat(1_000_000_000),
            };

            let user_takes_after = match user_takes_after {
                Some(amount) => amount as u16,
                None => 200,
            };

            let deposit_address = clementine_core::builder::address::generate_deposit_address(
                xonly_pk,
                &recovery_taproot_address,
                evm_address,
                bridge_amount,
                network,
                user_takes_after,
            )
            .expect("Failed to generate deposit address");

            println!("Deposit address: {}", deposit_address.0);
        }
        AggregatorCommands::GetTxParamsOfMoveTx { move_txid: _ } => {
            // TODO: Implement get_tx_params_of_move_tx handler
            println!("GetTxParamsOfMoveTx command not implemented yet");
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
