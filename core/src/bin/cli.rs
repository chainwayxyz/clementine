//! Command-line interface for Clementine node operators.
//!
//! This binary talks to running Clementine actor servers (aggregator, operator,
//! verifier). It is intended for node operators, not for end users of the
//! bridge.

use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::{
    address::NetworkUnchecked, hashes::Hash, secp256k1::SecretKey, Network, ScriptBuf, Txid,
    XOnlyPublicKey,
};
use bitcoincore_rpc::{json::SignRawTransactionInput, Auth, Client, RpcApi};
use clap::{Args, Parser, Subcommand};
use clementine_core::{
    actor::Actor,
    builder::transaction::TransactionType,
    config::BridgeConfig,
    deposit::SecurityCouncil,
    rpc::clementine::{
        self, clementine_aggregator_client::ClementineAggregatorClient, deposit::DepositData,
        entity_data_with_id::DataResult, AggregatorWithdrawalInput, BaseDeposit, Deposit, Empty,
        EntityStatus, EntityType, GetEntityStatusesRequest, Outpoint, ReplacementDeposit,
        SendMoveTxRequest, XOnlyPublicKeyRpc,
    },
    EVMAddress,
};
use tonic::Request;

/// Clementine CLI for node operators. Not intended for end users of the bridge.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The URL of the service
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
    /// Commands for interacting with Bitcoin only
    /// Give Bitcoin RPC URL as node-url
    Bitcoin {
        #[command(subcommand)]
        command: BitcoinCommands,
    },
    /// Print actor's taproot address and bitcoin wallet's new address
    PrintAddresses,
}

#[derive(Args)]
struct WithdrawalArgs {
    #[arg(long)]
    withdrawal_id: u32,
    #[arg(long)]
    input_signature: String,
    #[arg(long)]
    input_outpoint_txid: Txid,
    #[arg(long)]
    input_outpoint_vout: u32,
    #[arg(long, value_parser = parse_script_buf)]
    output_script_pubkey: ScriptBuf,
    #[arg(long)]
    output_amount: u64,
}

#[derive(Subcommand)]
enum OperatorCommands {
    /// Get operator parameters
    GetParams,
    /// Withdraw funds
    Withdraw {
        #[command(flatten)]
        withdrawal: WithdrawalArgs,
    },
    /// Get vergen build information
    Vergen,
    /// Get kickoff related txs for sending kickoff manually.
    /// On automated operator nodes this is only needed if automation fails.
    GetReimbursementTxs {
        #[arg(long)]
        deposit_outpoint_txid: Txid,
        #[arg(long)]
        deposit_outpoint_vout: u32,
    },
    /// Get compatibility parameters
    GetCompatibilityParams,
    /// Get entity status
    GetEntityStatus,
    // Add other operator commands as needed
}

#[derive(Subcommand)]
enum VerifierCommands {
    /// Get verifier parameters
    GetParams,
    /// Get compatibility parameters
    GetCompatibilityParams,
    /// Get entity status
    GetEntityStatus,
    /// Get vergen build information
    Vergen,
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
        deposit_outpoint_txid: Txid,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long, value_parser = parse_evm_address)]
        evm_address: EVMAddress,
        #[arg(long)]
        recovery_taproot_address: bitcoin::Address<NetworkUnchecked>,
    },
    /// Sign a replacement deposit
    NewReplacementDeposit {
        #[arg(long)]
        deposit_outpoint_txid: Txid,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        old_move_txid: Txid,
    },
    /// Get the aggregated NofN x-only public key
    GetNofnAggregatedKey,
    /// Get deposit address
    GetDepositAddress {
        #[arg(long, value_parser = parse_evm_address)]
        evm_address: EVMAddress,
        #[arg(long)]
        recovery_taproot_address: bitcoin::Address<NetworkUnchecked>,
        #[arg(long, default_value_t = Network::Regtest)]
        network: Network,
        #[arg(long, default_value_t = 200)]
        user_takes_after: u16,
    },
    GetReplacementDepositAddress {
        #[arg(long)]
        move_txid: Txid,
        #[arg(long, default_value_t = Network::Regtest)]
        network: Network,
        #[arg(long)]
        security_council: SecurityCouncil,
    },
    /// Process a new withdrawal
    NewWithdrawal {
        #[command(flatten)]
        withdrawal: WithdrawalArgs,
        #[arg(long)]
        verification_signature: Option<String>,
        #[arg(long, num_args = 1.., value_delimiter = ',')]
        operator_xonly_pks: Option<Vec<XOnlyPublicKey>>,
    },
    NewOptimisticWithdrawal {
        #[command(flatten)]
        withdrawal: WithdrawalArgs,
        #[arg(long)]
        verification_signature: Option<String>,
    },
    /// Get the status of all entities (operators and verifiers)
    GetEntityStatuses {
        #[arg(long)]
        restart_tasks: Option<bool>,
    },
    /// Internal command to get the stored encrypted emergency stop txs for the given move txids
    InternalGetEmergencyStopTx {
        #[arg(long, required = true, num_args = 1.., value_delimiter = ',')]
        /// A comma-separated list of move txids
        move_txids: Vec<Txid>,
    },
    /// Get compatibility parameters for all entities
    GetCompatibilityParamsFromAll,
    /// Get vergen build information
    Vergen,
}

#[derive(Subcommand)]
enum BitcoinCommands {
    /// Send a transaction with CPFP package
    SendTxWithCpfp {
        #[arg(long)]
        raw_tx: String,
        #[arg(long)]
        fee_payer_address: Option<bitcoin::Address<NetworkUnchecked>>,
        #[arg(long)]
        fee_rate: Option<f64>,
        #[arg(long)]
        bitcoin_rpc_user: String,
        #[arg(long)]
        bitcoin_rpc_password: String,
    },
}

fn get_path_from_env_or_default(env_var: &str, default: &str) -> PathBuf {
    let path = std::env::var(env_var);
    let path = match path {
        Ok(path) => {
            println!("Using cert path from environment variable {env_var}: {path}");
            path
        }
        Err(_) => {
            println!("Warning: {env_var} is not set, using default cert path: {default}.\nIf this path is incorrect, please set the environment variable {env_var} to the correct path or call the binary from the correct directory, or any aggregator/operator/verifier command may not work.");
            default.to_string()
        }
    };
    PathBuf::from(path)
}

// Create a minimal config with default TLS paths
fn create_minimal_config() -> BridgeConfig {
    // CLIENT_KEY_PATH env var will be used if it is set
    // CLIENT_CERT_PATH env var will be used if it is set
    // CA_CERT_PATH env var will be used if it is set
    BridgeConfig {
        ca_cert_path: get_path_from_env_or_default("CA_CERT_PATH", "core/certs/ca/ca.pem"),
        client_cert_path: get_path_from_env_or_default(
            "CLIENT_CERT_PATH",
            "core/certs/client/client.pem",
        ),
        client_key_path: get_path_from_env_or_default(
            "CLIENT_KEY_PATH",
            "core/certs/client/client.key",
        ),
        ..Default::default()
    }
}

fn parse_script_buf(script: &str) -> Result<ScriptBuf, String> {
    ScriptBuf::from_hex(script).map_err(|error| error.to_string())
}

fn parse_evm_address(address: &str) -> Result<EVMAddress, String> {
    alloy::primitives::Address::from_str(address)
        .map(|address| EVMAddress(address.into_array()))
        .map_err(|error| error.to_string())
}

fn rpc_outpoint(txid: Txid, vout: u32) -> Outpoint {
    Outpoint {
        txid: Some(txid.into()),
        vout,
    }
}

fn withdrawal_params_from_args(
    withdrawal: WithdrawalArgs,
) -> clementine_core::rpc::clementine::WithdrawParams {
    clementine_core::rpc::clementine::WithdrawParams {
        withdrawal_id: withdrawal.withdrawal_id,
        input_signature: hex::decode(withdrawal.input_signature)
            .expect("Failed to decode input signature"),
        input_outpoint: Some(rpc_outpoint(
            withdrawal.input_outpoint_txid,
            withdrawal.input_outpoint_vout,
        )),
        output_script_pubkey: withdrawal.output_script_pubkey.into_bytes(),
        output_amount: withdrawal.output_amount,
    }
}

async fn handle_operator_call(url: String, command: OperatorCommands) {
    let config = create_minimal_config();
    let mut operator = clementine_core::rpc::get_clients(
        vec![url],
        clementine_core::rpc::operator_client_builder(&config),
        &config,
        true,
    )
    .await
    .expect("Exists")[0]
        .clone();

    match command {
        OperatorCommands::GetParams => {
            let params = operator
                .get_params(Empty {})
                .await
                .expect("Failed to make a request to operator");
            println!("Operator params: {params:?}");
        }
        OperatorCommands::Withdraw { withdrawal } => {
            println!("Processing withdrawal with id {}", withdrawal.withdrawal_id);

            operator
                .internal_withdraw(Request::new(withdrawal_params_from_args(withdrawal)))
                .await
                .expect("Failed to make a request to operator");
        }
        OperatorCommands::Vergen => {
            let params = Empty {};
            let response = operator
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request to operator");
            let response_msg = response.into_inner().response;
            println!("Vergen response:\n{response_msg}");
        }
        OperatorCommands::GetReimbursementTxs {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
        } => {
            println!(
                "Getting kickoff txs for outpoint {deposit_outpoint_txid}:{deposit_outpoint_vout}"
            );
            let response = operator
                .get_reimbursement_txs(Request::new(rpc_outpoint(
                    deposit_outpoint_txid,
                    deposit_outpoint_vout,
                )))
                .await
                .expect("Failed to make a request to operator")
                .into_inner();
            for signed_tx in &response.signed_txs {
                let tx_type: TransactionType = signed_tx
                    .transaction_type
                    .expect("Tx type should not be None")
                    .try_into()
                    .expect("Failed to convert tx type");
                let transaction: bitcoin::Transaction =
                    bitcoin::consensus::deserialize(&signed_tx.raw_tx)
                        .expect("Failed to decode transaction");
                match tx_type {
                    TransactionType::Kickoff => {
                        println!("Round tx is on chain, time to send the kickoff tx. This tx is non-standard and cannot be sent by using normal Bitcoin RPC");
                    }
                    TransactionType::BurnUnusedKickoffConnectors => {
                        println!("To be able to send ready to reimburse tx, all unused kickoff connectors must be burned, otherwise the operator will get slashed.
                        This tx is standard and requires CPFP to be sent (last output is the anchor output)");
                    }
                    TransactionType::ReadyToReimburse => {
                        println!("All unused kickoff connectors are burned, and all live kickoffs kickoff finalizer utxo's are
                        spent, meaning it is safe to send ready to reimburse tx. This tx is standard and requires CPFP to be sent (last output is the anchor output)");
                    }
                    TransactionType::Reimburse => {
                        println!("Reimburse tx is ready to be sent. This tx is standard and requires CPFP to be sent (last output is the anchor output)");
                    }
                    TransactionType::ChallengeTimeout => {
                        println!("After kickoff, challenge timeout tx needs to be sent. Due to the timelock, it can only be sent after 216 blocks pass from the kickoff tx {}.
                        This tx is standard and requires CPFP to be sent (last output is the anchor output)",
                        transaction.input[0].previous_output.txid);
                    }
                    TransactionType::Round => {
                        println!("Time to send the round tx either for sending the kickoff tx, or getting the reimbursement for the past kickoff by advancing the round. Round tx is a non-standard tx and cannot be sent by using normal Bitcoin RPC.
                        If the round is not the first round, 216 number of blocks need to pass from the previous ready to reimburse tx {} (If this is not collateral)",
                        transaction.input[0].previous_output.txid);
                    }
                    _ => {}
                }
                let hex_tx = hex::encode(&signed_tx.raw_tx);
                println!("Tx type: {tx_type:?}, Tx hex: {hex_tx:?}");
            }
        }
        OperatorCommands::GetCompatibilityParams => {
            let params = operator
                .get_compatibility_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Compatibility params:\n{params:#?}");
        }
        OperatorCommands::GetEntityStatus => {
            let params = operator
                .get_current_status(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Entity status:\n{params:#?}");
        }
    }
}

async fn handle_verifier_call(url: String, command: VerifierCommands) {
    println!("Connecting to verifier at {url}");
    let config = create_minimal_config();
    let mut verifier = clementine_core::rpc::get_clients(
        vec![url],
        clementine_core::rpc::verifier_client_builder(&config),
        &config,
        true,
    )
    .await
    .expect("Exists")[0]
        .clone();

    match command {
        VerifierCommands::GetParams => {
            let params = verifier
                .get_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Verifier params: {params:?}");
        }
        VerifierCommands::Vergen => {
            let params = Empty {};
            let response = verifier
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            let response_msg = response.into_inner().response;
            println!("Vergen response:\n{response_msg}");
        }
        VerifierCommands::GetCompatibilityParams => {
            let params = verifier
                .get_compatibility_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Compatibility params:\n{params:#?}");
        }
        VerifierCommands::GetEntityStatus => {
            let params = verifier
                .get_current_status(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Entity status:\n{params:#?}");
        }
    }
}

async fn handle_aggregator_call(url: String, command: AggregatorCommands) {
    println!("Connecting to aggregator at {url}");
    let config = create_minimal_config();
    let mut aggregator = clementine_core::rpc::get_clients(
        vec![url],
        ClementineAggregatorClient::new,
        &config,
        false,
    )
    .await
    .expect("Exists")[0]
        .clone();

    match command {
        AggregatorCommands::Setup => {
            let setup = aggregator
                .setup(Empty {})
                .await
                .expect("Failed to make a request");
            println!("{setup:?}");
        }
        AggregatorCommands::GetCompatibilityParamsFromAll => {
            let params = aggregator
                .get_compatibility_data_from_entities(Empty {})
                .await
                .expect("Failed to make a request");
            let params = params.into_inner();
            println!("Compatibility params from all entities:");
            for entity in params.entities_compatibility_data {
                match entity.entity_id {
                    Some(entity_id) => {
                        let kind = EntityType::try_from(entity_id.kind)
                            .expect("Failed to convert kind to entity type");
                        println!("Entity: {:?}, ID: {:?}", kind, entity_id.id);
                    }
                    None => {
                        println!("No entity id received");
                    }
                }
                match entity.data_result {
                    Some(data_result) => match data_result {
                        DataResult::Data(data) => {
                            println!("{data:#?}");
                        }
                        DataResult::Error(error) => {
                            println!("Error: {error}");
                        }
                    },
                    None => {
                        println!("No data");
                    }
                }
            }
        }
        AggregatorCommands::NewDeposit {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            evm_address,
            recovery_taproot_address,
        } => {
            let deposit_outpoint = rpc_outpoint(deposit_outpoint_txid, deposit_outpoint_vout);

            let move_to_vault_tx = aggregator
                .new_deposit(Deposit {
                    deposit_outpoint: Some(deposit_outpoint.clone()),
                    deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                        evm_address: evm_address.0.to_vec(),
                        recovery_taproot_address: recovery_taproot_address
                            .assume_checked()
                            .to_string(),
                    })),
                })
                .await
                .expect("Failed to make a request");

            let move_to_vault_tx = move_to_vault_tx.into_inner();

            let deposit = aggregator
                .send_move_to_vault_tx(SendMoveTxRequest {
                    raw_tx: Some(move_to_vault_tx.clone()),
                    deposit_outpoint: Some(deposit_outpoint),
                })
                .await;

            match deposit {
                Ok(deposit) => {
                    let move_txid = deposit.get_ref().txid.clone();
                    let txid = bitcoin::Txid::from_byte_array(
                        move_txid
                            .try_into()
                            .expect("Failed to convert txid to array"),
                    );
                    println!("Move txid: {txid}");
                }
                Err(e) => {
                    println!("Failed to send move transaction: {e}");
                    println!(
                        "Please send manually: {}",
                        hex::encode(move_to_vault_tx.raw_tx)
                    );
                }
            }
        }
        AggregatorCommands::NewOptimisticWithdrawal {
            withdrawal,
            verification_signature,
        } => {
            println!("Processing withdrawal with id {}", withdrawal.withdrawal_id);

            let withdraw_params_with_sig =
                clementine_core::rpc::clementine::OptimisticWithdrawParams {
                    withdrawal: Some(withdrawal_params_from_args(withdrawal)),
                    verification_signature: verification_signature.clone(),
                };

            let response = aggregator
                .optimistic_payout(Request::new(withdraw_params_with_sig))
                .await
                .expect("Failed to make a request");
            println!("Tx: {}", hex::encode(response.get_ref().raw_tx.clone()));
        }
        AggregatorCommands::GetNofnAggregatedKey => {
            let response = aggregator
                .get_nofn_aggregated_xonly_pk(Request::new(Empty {}))
                .await
                .expect("Failed to make a request");
            let xonly_pk = bitcoin::XOnlyPublicKey::from_slice(&response.get_ref().nofn_xonly_pk)
                .expect("Failed to parse xonly_pk");
            println!("{xonly_pk}");
        }
        AggregatorCommands::GetDepositAddress {
            evm_address,
            recovery_taproot_address,
            network,
            user_takes_after,
        } => {
            let response = aggregator
                .get_nofn_aggregated_xonly_pk(Request::new(Empty {}))
                .await
                .expect("Failed to make a request");
            let xonly_pk = bitcoin::XOnlyPublicKey::from_slice(&response.get_ref().nofn_xonly_pk)
                .expect("Failed to parse xonly_pk");

            let deposit_address = clementine_core::builder::address::generate_deposit_address(
                xonly_pk,
                &recovery_taproot_address,
                evm_address,
                network,
                user_takes_after,
            )
            .expect("Failed to generate deposit address");

            let address = &deposit_address.0;
            println!("Deposit address: {address}");
        }
        AggregatorCommands::InternalGetEmergencyStopTx { move_txids } => {
            let emergency_stop_tx = aggregator
                .internal_get_emergency_stop_tx(Request::new(
                    clementine::GetEmergencyStopTxRequest {
                        txids: move_txids.clone().into_iter().map(Into::into).collect(),
                    },
                ))
                .await
                .expect("Failed to make a request");
            println!("Emergency stop tx: {emergency_stop_tx:?}");
            let response = emergency_stop_tx.into_inner();
            let mut returned_txids = Vec::new();
            for (txid, tx) in response
                .txids
                .into_iter()
                .zip(response.encrypted_emergency_stop_txs)
            {
                let txid = Txid::try_from(txid).expect("Failed to parse move txid");
                println!("Emergency stop tx for move tx {txid}: {}", hex::encode(tx));
                returned_txids.push(txid);
            }
            for txid in move_txids
                .iter()
                .filter(|txid| !returned_txids.contains(txid))
            {
                println!("No emergency stop tx stored for move tx {txid}");
            }
        }
        AggregatorCommands::GetReplacementDepositAddress {
            move_txid,
            network,
            security_council,
        } => {
            let response = aggregator
                .get_nofn_aggregated_xonly_pk(Request::new(Empty {}))
                .await
                .expect("Failed to make a request");

            let nofn_xonly_pk =
                bitcoin::XOnlyPublicKey::from_slice(&response.get_ref().nofn_xonly_pk)
                    .expect("Failed to parse xonly_pk");

            let (replacement_deposit_address, _) =
                clementine_core::builder::address::generate_replacement_deposit_address(
                    move_txid,
                    nofn_xonly_pk,
                    network,
                    security_council,
                )
                .expect("Failed to generate replacement deposit address");

            println!("Replacement deposit address: {replacement_deposit_address}");
        }
        AggregatorCommands::NewReplacementDeposit {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            old_move_txid,
        } => {
            let deposit_outpoint = rpc_outpoint(deposit_outpoint_txid, deposit_outpoint_vout);

            let deposit = aggregator
                .new_deposit(Deposit {
                    deposit_outpoint: Some(deposit_outpoint.clone()),
                    deposit_data: Some(DepositData::ReplacementDeposit(ReplacementDeposit {
                        old_move_txid: Some(old_move_txid.into()),
                    })),
                })
                .await
                .expect("Failed to make a request");
            let deposit = aggregator
                .send_move_to_vault_tx(SendMoveTxRequest {
                    raw_tx: Some(deposit.into_inner()),
                    deposit_outpoint: Some(deposit_outpoint),
                })
                .await
                .expect("Failed to make a request");
            let move_txid = deposit.get_ref().txid.clone();
            let txid = bitcoin::Txid::from_byte_array(
                move_txid
                    .try_into()
                    .expect("Failed to convert txid to array"),
            );
            println!("Move txid: {txid}");
        }
        AggregatorCommands::NewWithdrawal {
            withdrawal,
            verification_signature,
            operator_xonly_pks,
        } => {
            println!("Processing withdrawal with id {}", withdrawal.withdrawal_id);

            let withdraw_params_with_sig =
                clementine_core::rpc::clementine::WithdrawParamsWithSig {
                    withdrawal: Some(withdrawal_params_from_args(withdrawal)),
                    verification_signature,
                };

            let operator_xonly_pks = operator_xonly_pks
                .unwrap_or_default()
                .into_iter()
                .map(XOnlyPublicKeyRpc::from)
                .collect::<Vec<_>>();

            let response = aggregator
                .withdraw(Request::new(AggregatorWithdrawalInput {
                    withdrawal: Some(withdraw_params_with_sig),
                    operator_xonly_pks,
                }))
                .await
                .expect("Failed to make a request");

            let withdraw_responses = response.get_ref().withdraw_responses.clone();

            for (i, result) in withdraw_responses.iter().enumerate() {
                println!("Operator {i}: {result:?}");
            }
        }
        AggregatorCommands::GetEntityStatuses { restart_tasks } => {
            let restart_tasks = restart_tasks.unwrap_or(false);
            let request = GetEntityStatusesRequest { restart_tasks };

            let response = aggregator
                .get_entity_statuses(Request::new(request))
                .await
                .expect("Failed to make a request");

            println!("Entities status:");
            for entity_status in &response.get_ref().entity_statuses {
                match &entity_status.entity_id {
                    Some(entity_id) => {
                        let kind = EntityType::try_from(entity_id.kind)
                            .expect("Failed to convert kind to entity type");
                        println!("Entity: {:?}, ID: {:?}", kind, entity_id.id);
                        match &entity_status.status_result {
                            Some(clementine_core::rpc::clementine::entity_status_with_id::StatusResult::Status(status)) => {
                                let EntityStatus {
                                    automation,
                                    wallet_balance,
                                    tx_sender_synced_height,
                                    finalized_synced_height,
                                    hcp_last_proven_height,
                                    rpc_tip_height,
                                    bitcoin_syncer_synced_height,
                                    state_manager_next_height,
                                    stopped_tasks,
                                    btc_fee_rate_sat_vb,
                                    lcp_synced_height,
                                } = &status;
                                println!("  Automation: {automation}");
                                let wallet_balance = wallet_balance
                                    .as_ref()
                                    .map_or("N/A".to_string(), |s| s.clone());
                                println!("  Wallet balance: {wallet_balance}");
                                let btc_fee_rate_sat_vb = btc_fee_rate_sat_vb
                                    .map_or("N/A".to_string(), |r| r.to_string());
                                println!("  BTC fee rate: {btc_fee_rate_sat_vb} sat/vB");
                                let tx_sender_height = tx_sender_synced_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  TX sender synced height: {tx_sender_height}");
                                let finalized_height = finalized_synced_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  Finalized synced height: {finalized_height}");
                                let hcp_height = hcp_last_proven_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  HCP last proven height: {hcp_height}");
                                let rpc_tip_height = rpc_tip_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  RPC tip height: {rpc_tip_height}");
                                let bitcoin_syncer_height = bitcoin_syncer_synced_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  Bitcoin syncer synced height: {bitcoin_syncer_height}");
                                let state_manager_height = state_manager_next_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  State manager next height: {state_manager_height}");
                                let lcp_height = lcp_synced_height
                                    .map_or("N/A".to_string(), |h| h.to_string());
                                println!("  LCP synced height: {lcp_height}");
                                if !stopped_tasks.as_ref().is_none_or(|t| t.stopped_tasks.is_empty()) {
                                    let stopped_tasks = &stopped_tasks
                                        .as_ref()
                                        .expect("Stopped tasks are required")
                                        .stopped_tasks;
                                    println!("  Stopped tasks: {stopped_tasks:?}");
                                }
                            }
                            Some(clementine_core::rpc::clementine::entity_status_with_id::StatusResult::Err(error)) => {
                                let error_msg = &error.error;
                                println!("  Error: {error_msg}");
                            }
                            None => {
                                println!("  No status available");
                            }
                        }
                    }
                    None => {
                        println!("Entity: Unknown");
                    }
                }
                println!();
            }

            if restart_tasks {
                println!("Tasks restart was requested and included in the request.");
            }
        }
        AggregatorCommands::Vergen => {
            let params = Empty {};
            let response = aggregator
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            let response_msg = response.into_inner().response;
            println!("Vergen response:\n{response_msg}");
        }
    }
}

async fn handle_print_addresses() {
    // Get secret key from environment
    let secret_key = match std::env::var("SECRET_KEY") {
        Ok(key) => SecretKey::from_str(&key).expect("Failed to parse secret key"),
        Err(_) => {
            println!("Error: SECRET_KEY environment variable not set");
            return;
        }
    };

    // Get Bitcoin RPC credentials from environment
    let bitcoin_rpc_url = match std::env::var("BITCOIN_RPC_URL") {
        Ok(url) => url,
        Err(_) => {
            println!("Error: BITCOIN_RPC_URL environment variable not set");
            return;
        }
    };
    let bitcoin_rpc_user = match std::env::var("BITCOIN_RPC_USER") {
        Ok(user) => user,
        Err(_) => {
            println!("Error: BITCOIN_RPC_USER environment variable not set");
            return;
        }
    };
    let bitcoin_rpc_password = match std::env::var("BITCOIN_RPC_PASSWORD") {
        Ok(password) => password,
        Err(_) => {
            println!("Error: BITCOIN_RPC_PASSWORD environment variable not set");
            return;
        }
    };

    // Get network from environment or default to regtest
    let network = match std::env::var("NETWORK") {
        Ok(network) => Network::from_str(&network).unwrap_or(Network::Regtest),
        Err(_) => Network::Regtest,
    };

    let actor = Actor::new(secret_key, network);
    let taproot_address = actor.address;
    println!("Actor's taproot address: {taproot_address}");

    // Connect to Bitcoin RPC and get new address
    let rpc = match Client::new(
        &bitcoin_rpc_url,
        Auth::UserPass(bitcoin_rpc_user, bitcoin_rpc_password),
    )
    .await
    {
        Ok(client) => client,
        Err(e) => {
            println!("Error connecting to Bitcoin RPC: {e}");
            return;
        }
    };

    match rpc
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
        .await
    {
        Ok(address) => {
            let addr = address.assume_checked();
            println!("Bitcoin wallet's new address: {addr}");
        }
        Err(e) => println!("Error getting new address from Bitcoin wallet: {e}"),
    }
}

async fn handle_bitcoin_call(url: String, command: BitcoinCommands) {
    match command {
        BitcoinCommands::SendTxWithCpfp {
            raw_tx,
            fee_payer_address,
            fee_rate,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
        } => {
            let tx_hex = hex::decode(raw_tx).expect("Failed to decode transaction");
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_hex)
                .expect("Failed to deserialize transaction");

            let txid = tx.compute_txid();
            println!("Transaction created: {txid}");
            let raw_tx = hex::encode(tx_hex);
            println!("Raw transaction: {raw_tx}");

            // Find P2A anchor output (script: 51024e73)
            let p2a_vout = tx
                .output
                .iter()
                .position(|output| {
                    output.script_pubkey == ScriptBuf::from_hex("51024e73").expect("valid script")
                })
                .expect("P2A anchor output not found in transaction");

            let p2a_txout = tx.output[p2a_vout].clone();

            println!("Found P2A anchor output at vout: {p2a_vout}");

            // Connect to Bitcoin RPC
            use bitcoincore_rpc::{Auth, Client, RpcApi};
            let rpc = Client::new(&url, Auth::UserPass(bitcoin_rpc_user, bitcoin_rpc_password))
                .await
                .expect("Failed to connect to Bitcoin RPC");

            let Some(fee_payer_address) = fee_payer_address else {
                let temp_address = rpc
                    .get_new_address(
                        Some("fee_payer_address"),
                        Some(bitcoincore_rpc::json::AddressType::Bech32m),
                    )
                    .await
                    .expect("Failed to get new address");
                println!(
                    "You haven't provided a fee payer address, so a new one was generated: {}",
                    temp_address.assume_checked()
                );
                println!("Please use this address for the fee payer in the next command");
                return;
            };

            let fee_payer_address = fee_payer_address.assume_checked();

            let fee_rate_sat_vb = fee_rate.unwrap_or(10.0) as u64;

            // Calculate package fee requirements
            let parent_weight = tx.weight();
            // empirical - tx with 1 anchor, 1 taproot input + 1 change taproot output had 540 WU
            let estimated_child_weight = bitcoin::Weight::from_wu(540);
            let total_weight = parent_weight + estimated_child_weight;
            let required_fee_sats =
                (total_weight.to_wu() as f64 * fee_rate_sat_vb as f64 / 4.0) as u64;
            let required_fee = bitcoin::Amount::from_sat(required_fee_sats);

            println!(
                "Parent weight: {parent_weight}, estimated total: {total_weight}, required fee: {} sats",
                required_fee.to_sat()
            );

            let unspent = rpc
                .list_unspent(
                    Some(1),
                    Some(999999999),
                    Some(&[&fee_payer_address.clone()]),
                    None,
                    None,
                )
                .await
                .expect("Failed to list unspent outputs");

            if unspent.is_empty() {
                let unspent = rpc
                    .list_unspent(None, None, Some(&[&fee_payer_address.clone()]), None, None)
                    .await
                    .expect("Failed to list unspent outputs");
                if unspent.is_empty() {
                    println!("No unspent outputs available for fee payment.");
                    println!("Please send some funds to the fee payer address.");
                    println!("Fee payer address: {fee_payer_address}");
                } else {
                    println!("Unspent outputs: {unspent:?}");
                    println!("Please wait for them to confirm.");
                }
                return;
            }

            let fee_payer_utxo = unspent
                .iter()
                .find(|utxo| utxo.amount > required_fee)
                .unwrap_or_else(|| {
                    panic!(
                        "No UTXO found with enough balance for fee payment, required fee is: {required_fee}"
                    )
                });

            // Create child transaction
            use bitcoin::{transaction::Version, OutPoint, Sequence, TxIn, TxOut};

            let child_input = TxIn {
                previous_output: OutPoint {
                    txid: tx.compute_txid(),
                    vout: p2a_vout as u32,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let fee_payer_input = TxIn {
                previous_output: OutPoint {
                    txid: fee_payer_utxo.txid,
                    vout: fee_payer_utxo.vout,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };

            let total_input_value = p2a_txout.value + fee_payer_utxo.amount;
            let change_amount = total_input_value
                .checked_sub(required_fee)
                .expect("Insufficient funds for required fee");

            let child_output = TxOut {
                value: change_amount,
                script_pubkey: fee_payer_address.script_pubkey(),
            };

            let child_input_utxo = SignRawTransactionInput {
                txid: child_input.previous_output.txid,
                vout: child_input.previous_output.vout,
                script_pub_key: p2a_txout.script_pubkey,
                redeem_script: None,
                amount: Some(p2a_txout.value),
            };

            let child_tx = bitcoin::Transaction {
                version: Version::non_standard(3),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![child_input, fee_payer_input],
                output: vec![child_output],
            };

            let signed_tx = rpc
                .sign_raw_transaction_with_wallet(&child_tx, Some(&[child_input_utxo]), None)
                .await
                .expect("Failed to sign child transaction");

            let signed_child_tx = signed_tx
                .transaction()
                .expect("Failed to get transaction from sign_raw_transaction_with_wallet");

            println!(
                "Child transaction signed: {}",
                signed_child_tx.compute_txid()
            );

            // Submit CPFP package
            let package = vec![&tx, &signed_child_tx];
            println!("Submitting CPFP package");

            match rpc
                .submit_package(&package, Some(bitcoin::Amount::ZERO), None)
                .await
            {
                Ok(result) => {
                    println!("CPFP package submitted successfully");
                    println!("Package result: {result:?}");
                    let parent_txid = tx.compute_txid();
                    println!("Parent transaction TXID: {parent_txid}");
                    let child_txid = signed_child_tx.compute_txid();
                    println!("Child transaction TXID: {child_txid}");
                }
                Err(e) => {
                    println!("Failed to submit CPFP package: {e}");
                    println!("Manual submission options:");
                    println!(
                        "Parent tx: {}",
                        hex::encode(bitcoin::consensus::serialize(&tx))
                    );
                    println!(
                        "Child tx: {}",
                        hex::encode(bitcoin::consensus::serialize(&signed_child_tx))
                    );
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
        Commands::Bitcoin { command } => {
            handle_bitcoin_call(cli.node_url, command).await;
        }
        Commands::PrintAddresses => {
            handle_print_addresses().await;
        }
    }
}
