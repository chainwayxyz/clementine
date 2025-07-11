//! This module defines a command line interface for the RPC client.

use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::{hashes::Hash, Block, ScriptBuf, Txid};
use clap::{Parser, Subcommand};
use clementine_core::{
    config::BridgeConfig,
    deposit::SecurityCouncil,
    errors::BridgeError,
    rpc::clementine::{
        self, clementine_aggregator_client::ClementineAggregatorClient,
        clementine_operator_client::ClementineOperatorClient,
        clementine_verifier_client::ClementineVerifierClient, deposit::DepositData, Actors,
        BaseDeposit, Deposit, Empty, Outpoint, ReplacementDeposit, SendMoveTxRequest,
        VerifierPublicKeys, XOnlyPublicKeys,
    },
    EVMAddress,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Get vergen build information
    Vergen,
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
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        evm_address: Option<String>,
        #[arg(long)]
        recovery_taproot_address: Option<String>,
    },
    /// Get move transaction for deposit without sending it
    GetMoveTransaction {
        #[arg(long)]
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        evm_address: Option<String>,
        #[arg(long)]
        recovery_taproot_address: Option<String>,
    },
    /// Send move transaction using CPFP package
    SendMoveTransactionCPFP {
        #[arg(long)]
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        evm_address: Option<String>,
        #[arg(long)]
        recovery_taproot_address: Option<String>,
        #[arg(long)]
        fee_rate: Option<f64>, // sat/vB
        #[arg(long)]
        bitcoin_rpc_url: String,
        #[arg(long)]
        bitcoin_rpc_user: String,
        #[arg(long)]
        bitcoin_rpc_password: String,
    },
    NewReplacementDeposit {
        #[arg(long)]
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
        #[arg(long)]
        old_move_txid: String,
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
        user_takes_after: Option<u64>,
    },
    /// Get transaction parameters of a move transaction
    GetTxParamsOfMoveTx {
        #[arg(long)]
        bitcoin_rpc_url: String,
        #[arg(long)]
        bitcoin_rpc_user: String,
        #[arg(long)]
        bitcoin_rpc_password: String,
        #[arg(long)]
        move_txid: String,
    },
    GetReplacementDepositAddress {
        #[arg(long)]
        move_txid: String,
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        security_council: Option<SecurityCouncil>,
    },
    /// Process a new withdrawal
    NewWithdrawal {
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
    /// Get vergen build information
    Vergen,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinMerkleTree {
    depth: u32,
    nodes: Vec<Vec<[u8; 32]>>,
}

impl BitcoinMerkleTree {
    pub fn new(transactions: Vec<[u8; 32]>) -> Self {
        // assert!(depth > 0, "Depth must be greater than 0");
        // assert!(depth <= 254, "Depth must be less than or equal to 254");
        // assert!(
        //     u32::pow(2, (depth) as u32) >= transactions.len() as u32,
        //     "Too many transactions for this depth"
        // );
        let depth = (transactions.len() - 1).ilog(2) + 1;
        let mut tree = BitcoinMerkleTree {
            depth,
            nodes: vec![],
        };

        // Populate leaf nodes
        tree.nodes.push(vec![]);
        for tx in transactions.iter() {
            tree.nodes[0].push(*tx);
        }

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = transactions.len();
        let mut prev_level_index_offset = 0;
        let mut preimage: [u8; 64] = [0; 64];
        while prev_level_size > 1 {
            // println!("curr_level_offset: {}", curr_level_offset);
            // println!("prev_level_size: {}", prev_level_size);
            // println!("prev_level_index_offset: {}", prev_level_index_offset);
            tree.nodes.push(vec![]);
            for i in 0..(prev_level_size / 2) {
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1_usize][prev_level_index_offset + i * 2],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2 + 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            curr_level_offset += 1;
            prev_level_size = prev_level_size.div_ceil(2);
            prev_level_index_offset = 0;
        }
        tree
    }

    // Returns the Merkle root
    pub fn root(&self) -> [u8; 32] {
        self.nodes[self.nodes.len() - 1][0]
    }

    pub fn get_idx_path(&self, index: u32) -> Vec<[u8; 32]> {
        assert!(index < self.nodes[0].len() as u32, "Index out of bounds");
        let mut path = vec![];
        let mut level = 0;
        let mut i = index;
        while level < self.nodes.len() as u32 - 1 {
            if i % 2 == 1 {
                path.push(self.nodes[level as usize][i as usize - 1]);
            } else if (self.nodes[level as usize].len() - 1) as u32 == i {
                path.push(self.nodes[level as usize][i as usize]);
            } else {
                path.push(self.nodes[level as usize][(i + 1) as usize]);
            }

            level += 1;
            i /= 2;
        }

        path
    }

    pub fn calculate_root_with_merkle_proof(
        &self,
        txid: [u8; 32],
        idx: u32,
        merkle_proof: Vec<[u8; 32]>,
    ) -> [u8; 32] {
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = txid;
        let mut index = idx;
        let mut level: u32 = 0;
        while level < self.depth {
            if index % 2 == 0 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize]);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                preimage[..32].copy_from_slice(&merkle_proof[level as usize]);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
            index /= 2;
        }
        combined_hash
    }
}

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

fn _get_block_merkle_proof(
    block: Block,
    target_txid: Txid,
) -> Result<(usize, Vec<u8>), BridgeError> {
    let mut txid_index = 0;
    let txids = block
        .txdata
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            if tx.compute_txid() == target_txid {
                txid_index = i;
            }

            if i == 0 {
                [0; 32]
            } else {
                let wtxid = tx.compute_wtxid();
                wtxid.as_byte_array().to_owned()
            }
        })
        .collect::<Vec<_>>();

    let merkle_tree = BitcoinMerkleTree::new(txids.clone());
    let _witness_root = block.witness_root().expect("Failed to get witness root");
    let witness_idx_path =
        merkle_tree.get_idx_path(txid_index.try_into().expect("Failed to convert index"));

    let _root = merkle_tree.calculate_root_with_merkle_proof(
        txids[txid_index],
        txid_index.try_into().expect("Failed to convert index"),
        witness_idx_path.clone(),
    );

    Ok((txid_index, witness_idx_path.into_iter().flatten().collect()))
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

// Helper function to create move transaction from deposit parameters
async fn create_move_transaction(
    aggregator: &mut ClementineAggregatorClient<tonic::transport::Channel>,
    deposit_outpoint_txid: String,
    deposit_outpoint_vout: u32,
    evm_address: Option<String>,
    recovery_taproot_address: Option<String>,
) -> Result<clementine_core::rpc::clementine::RawSignedTx, Box<dyn std::error::Error>> {
    let evm_address = match evm_address {
        Some(address) => EVMAddress(
            hex::decode(address)?
                .try_into()
                .map_err(|_| "Invalid EVM address length")?,
        ),
        None => EVMAddress([1; 20]),
    };

    let recovery_taproot_address = match recovery_taproot_address {
        Some(address) => bitcoin::Address::from_str(&address)?,
        None => bitcoin::Address::from_str(
            "tb1p9k6y4my6vacczcyc4ph2m5q96hnxt5qlrqd9484qd9cwgrasc54qw56tuh",
        )?,
    };

    let mut deposit_outpoint_txid = hex::decode(deposit_outpoint_txid)?;
    deposit_outpoint_txid.reverse();

    let deposit = aggregator
        .new_deposit(Deposit {
            deposit_outpoint: Some(Outpoint {
                txid: Some(clementine_core::rpc::clementine::Txid {
                    txid: deposit_outpoint_txid,
                }),
                vout: deposit_outpoint_vout,
            }),
            deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                evm_address: evm_address.0.to_vec(),
                recovery_taproot_address: recovery_taproot_address.assume_checked().to_string(),
            })),
        })
        .await?;

    Ok(deposit.into_inner())
}

async fn handle_operator_call(url: String, command: OperatorCommands) {
    let config = create_minimal_config();
    let mut operator =
        clementine_core::rpc::get_clients(vec![url], ClementineOperatorClient::new, &config, true)
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
                security_council: Some(clementine::SecurityCouncil {
                    pks: vec![],
                    threshold: 0,
                }),
                deposit: Some(Deposit {
                    deposit_outpoint: Some(Outpoint {
                        txid: Some(clementine::Txid {
                            txid: hex::decode(deposit_outpoint_txid)
                                .expect("Failed to decode txid"),
                        }),
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
                    txid: Some(clementine_core::rpc::clementine::Txid {
                        txid: hex::decode(input_outpoint_txid).expect("Failed to decode txid"),
                    }),
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
        OperatorCommands::Vergen => {
            let params = Empty {};
            let response = operator
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Vergen response:\n{}", response.into_inner().response);
        }
    }
}

async fn handle_verifier_call(url: String, command: VerifierCommands) {
    println!("Connecting to verifier at {}", url);
    let config = create_minimal_config();
    let mut verifier =
        clementine_core::rpc::get_clients(vec![url], ClementineVerifierClient::new, &config, true)
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
        VerifierCommands::Vergen => {
            let params = Empty {};
            let response = verifier
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Vergen response:\n{}", response.into_inner().response);
        }
    }
}

async fn handle_aggregator_call(url: String, command: AggregatorCommands) {
    println!("Connecting to aggregator at {}", url);
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
                        txid: Some(clementine_core::rpc::clementine::Txid {
                            txid: deposit_outpoint_txid.clone(),
                        }),
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
            let deposit = aggregator
                .send_move_to_vault_tx(SendMoveTxRequest {
                    raw_tx: Some(deposit.into_inner()),
                    deposit_outpoint: Some(Outpoint {
                        txid: Some(clementine_core::rpc::clementine::Txid {
                            txid: deposit_outpoint_txid,
                        }),
                        vout: deposit_outpoint_vout,
                    }),
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
        AggregatorCommands::GetMoveTransaction {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            evm_address,
            recovery_taproot_address,
        } => {
            let raw_tx = create_move_transaction(
                &mut aggregator,
                deposit_outpoint_txid,
                deposit_outpoint_vout,
                evm_address,
                recovery_taproot_address,
            )
            .await
            .expect("Failed to create move transaction");

            let raw_tx_hex = hex::encode(&raw_tx.raw_tx);

            println!("Move transaction created successfully");
            println!("Raw transaction: {}", raw_tx_hex);
            println!();
            println!("Manual Bitcoin RPC commands:");
            println!("# Decode and verify the transaction:");
            println!("bitcoin-cli -regtest -rpcport=18443 -rpcuser=admin -rpcpassword=admin decoderawtransaction {}", raw_tx_hex);
            println!();
            println!("# Broadcast the transaction:");
            println!("bitcoin-cli -regtest -rpcport=18443 -rpcuser=admin -rpcpassword=admin sendrawtransaction {}", raw_tx_hex);
            println!();
            println!("# Mine a block to confirm:");
            println!(
                "bitcoin-cli -regtest -rpcport=18443 -rpcuser=admin -rpcpassword=admin -generate 1"
            );
        }
        AggregatorCommands::SendMoveTransactionCPFP {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            evm_address,
            recovery_taproot_address,
            fee_rate,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
        } => {
            let raw_tx = create_move_transaction(
                &mut aggregator,
                deposit_outpoint_txid,
                deposit_outpoint_vout,
                evm_address,
                recovery_taproot_address,
            )
            .await
            .expect("Failed to create move transaction");

            let move_tx_hex = hex::encode(&raw_tx.raw_tx);
            let move_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw_tx.raw_tx)
                .expect("Failed to deserialize move transaction");

            println!("Move transaction created: {}", move_tx.compute_txid());
            println!("Raw transaction: {}", move_tx_hex);

            // Find P2A anchor output (script: 51024e73)
            let p2a_vout = move_tx
                .output
                .iter()
                .position(|output| {
                    output.script_pubkey == ScriptBuf::from_hex("51024e73").expect("valid script")
                })
                .expect("P2A anchor output not found in move transaction");

            println!("Found P2A anchor output at vout: {}", p2a_vout);

            // Connect to Bitcoin RPC
            use bitcoincore_rpc::{Auth, Client, RpcApi};
            let rpc = Client::new(
                &bitcoin_rpc_url,
                Auth::UserPass(bitcoin_rpc_user, bitcoin_rpc_password),
            )
            .await
            .expect("Failed to connect to Bitcoin RPC");

            let temp_address = rpc
                .get_new_address(None, None)
                .await
                .expect("Failed to get new address");

            let fee_rate_sat_vb = fee_rate.unwrap_or(10.0) as u64;

            // Calculate package fee requirements
            let parent_weight = move_tx.weight();
            let estimated_child_weight = bitcoin::Weight::from_wu(500);
            let total_weight = parent_weight + estimated_child_weight;
            let required_fee_sats =
                (total_weight.to_wu() as f64 * fee_rate_sat_vb as f64 / 4.0) as u64;
            let required_fee = bitcoin::Amount::from_sat(required_fee_sats);

            println!(
                "Parent weight: {}, estimated total: {}, required fee: {} sats",
                parent_weight,
                total_weight,
                required_fee.to_sat()
            );

            // Generate blocks to ensure fresh UTXOs for fees
            println!("Generating blocks to create fresh UTXOs for CPFP");
            let blocks_generated = rpc
                .generate_to_address(1, &temp_address.clone().assume_checked())
                .await
                .expect("Failed to generate blocks");
            println!("Generated {} block(s)", blocks_generated.len());

            let unspent = rpc
                .list_unspent(None, None, None, None, None)
                .await
                .expect("Failed to list unspent outputs");

            if unspent.is_empty() {
                println!("No unspent outputs available for fee payment");
                return;
            }

            let fee_payer_utxo = unspent.last().expect("Checked unspent is not empty");
            println!(
                "Using UTXO {} for fees: {}",
                fee_payer_utxo.txid, fee_payer_utxo.amount
            );

            // Create child transaction
            use bitcoin::{transaction::Version, OutPoint, Sequence, TxIn, TxOut};

            let child_input = TxIn {
                previous_output: OutPoint {
                    txid: move_tx.compute_txid(),
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

            let total_input_value = bitcoin::Amount::from_sat(240) + fee_payer_utxo.amount;
            let change_amount = total_input_value
                .checked_sub(required_fee)
                .expect("Insufficient funds for required fee");

            let child_output = TxOut {
                value: change_amount,
                script_pubkey: temp_address.assume_checked().script_pubkey(),
            };

            let child_tx = bitcoin::Transaction {
                version: Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![child_input, fee_payer_input],
                output: vec![child_output],
            };

            println!("Child transaction created: {}", child_tx.compute_txid());

            // Submit CPFP package
            let package = vec![&move_tx, &child_tx];
            println!("Submitting CPFP package");

            match rpc
                .submit_package(&package, Some(bitcoin::Amount::ZERO), None)
                .await
            {
                Ok(result) => {
                    println!("CPFP package submitted successfully");
                    println!("Package result: {:?}", result);
                    println!("Move transaction TXID: {}", move_tx.compute_txid());
                    println!("Child transaction TXID: {}", child_tx.compute_txid());
                }
                Err(e) => {
                    println!("Failed to submit CPFP package: {}", e);
                    println!("Manual submission options:");
                    println!("Parent tx: {}", move_tx_hex);
                    println!(
                        "Child tx: {}",
                        hex::encode(bitcoin::consensus::serialize(&child_tx))
                    );
                }
            }
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

            let user_takes_after = match user_takes_after {
                Some(amount) => amount as u16,
                None => 200,
            };

            let deposit_address = clementine_core::builder::address::generate_deposit_address(
                xonly_pk,
                &recovery_taproot_address,
                evm_address,
                network,
                user_takes_after,
            )
            .expect("Failed to generate deposit address");

            println!("Deposit address: {}", deposit_address.0);
        }
        AggregatorCommands::GetTxParamsOfMoveTx {
            bitcoin_rpc_url: _,
            bitcoin_rpc_user: _,
            bitcoin_rpc_password: _,
            move_txid: _,
        } => {
            unimplemented!()
            // let extended_rpc = extended_rpc::ExtendedRpc::connect(
            //     bitcoin_rpc_url,
            //     bitcoin_rpc_user,
            //     bitcoin_rpc_password,
            // )
            // .await
            // .expect("Failed to connect to Bitcoin RPC");

            // let flag: u16 = 1;

            // let tx_id: &bitcoin::Txid =
            //     &bitcoin::Txid::from_str(&move_txid).expect("Failed to parse txid");

            // let tx = extended_rpc
            //     .get_tx_of_txid(tx_id)
            //     .await
            //     .expect("Failed to get tx of txid");

            // let block_hash = extended_rpc
            //     .get_blockhash_of_tx(tx_id)
            //     .await
            //     .expect("Failed to get block hash");

            // let version = (tx.version.0 as u32).to_le_bytes();

            // let block = extended_rpc
            //     .client
            //     .get_block(&block_hash)
            //     .await
            //     .expect("Failed to get block");

            // let block_height = block
            //     .bip34_block_height()
            //     .expect("Failed to get block height");

            // let (index, merkle_proof) =
            //     get_block_merkle_proof(block, *tx_id).expect("Failed to get block merkle proof");

            // let vin: Vec<u8> = tx
            //     .input
            //     .iter()
            //     .map(|input| {
            //         let mut encoded_input = Vec::new();
            //         let mut previous_output = Vec::new();
            //         input
            //             .previous_output
            //             .consensus_encode(&mut previous_output)
            //             .expect("Failed to encode previous output");
            //         let mut script_sig = Vec::new();
            //         input
            //             .script_sig
            //             .consensus_encode(&mut script_sig)
            //             .expect("Failed to encode script sig");
            //         let mut sequence = Vec::new();
            //         input
            //             .sequence
            //             .consensus_encode(&mut sequence)
            //             .expect("Failed to encode sequence");

            //         encoded_input.extend(previous_output);
            //         encoded_input.extend(script_sig);
            //         encoded_input.extend(sequence);

            //         Ok::<Vec<u8>, BridgeError>(encoded_input)
            //     })
            //     .collect::<Result<Vec<_>, _>>()
            //     .expect("Failed to encode input")
            //     .into_iter()
            //     .flatten()
            //     .collect::<Vec<u8>>();

            // let vin = [vec![tx.input.len() as u8], vin].concat();

            // let vout: Vec<u8> = tx
            //     .output
            //     .iter()
            //     .map(|param| {
            //         let mut raw = Vec::new();
            //         param
            //             .consensus_encode(&mut raw)
            //             .map_err(|e| eyre::eyre!("Can't encode param: {}", e))?;

            //         Ok::<Vec<u8>, BridgeError>(raw)
            //     })
            //     .collect::<Result<Vec<_>, _>>()
            //     .expect("Failed to encode output")
            //     .into_iter()
            //     .flatten()
            //     .collect::<Vec<u8>>();
            // let vout = [vec![tx.output.len() as u8], vout].concat();

            // let witness: Vec<u8> =
            //     tx.input
            //         .iter()
            //         .map(|param| {
            //             let mut raw = Vec::new();
            //             param.witness.consensus_encode(&mut raw).map_err(|e| {
            //                 eyre::eyre!("Can't encode param: {}", e)
            //             })?;

            //             Ok::<Vec<u8>, BridgeError>(raw)
            //         })
            //         .collect::<Result<Vec<_>, _>>()
            //         .expect("Failed to encode witness")
            //         .into_iter()
            //         .flatten()
            //         .collect::<Vec<u8>>();

            // let lock_time = tx.lock_time.to_consensus_u32();

            // unimplemented!()
            // println!("Transaction params: {:?}", tx_params);
        }
        AggregatorCommands::GetReplacementDepositAddress {
            move_txid,
            network,
            security_council,
        } => {
            let mut move_txid = hex::decode(move_txid).expect("Failed to decode txid");
            move_txid.reverse();
            let move_txid = bitcoin::Txid::from_byte_array(
                move_txid
                    .try_into()
                    .expect("Failed to convert txid to array"),
            );

            let response = aggregator
                .get_nofn_aggregated_xonly_pk(Request::new(Empty {}))
                .await
                .expect("Failed to make a request");

            let nofn_xonly_pk =
                bitcoin::XOnlyPublicKey::from_slice(&response.get_ref().nofn_xonly_pk)
                    .expect("Failed to parse xonly_pk");

            let network = match network {
                Some(network) => {
                    bitcoin::Network::from_str(&network).expect("Failed to parse network")
                }
                None => bitcoin::Network::Regtest,
            };

            let (replacement_deposit_address, _) =
                clementine_core::builder::address::generate_replacement_deposit_address(
                    move_txid,
                    nofn_xonly_pk,
                    network,
                    security_council.expect("Security council is required"),
                )
                .expect("Failed to generate replacement deposit address");

            println!(
                "Replacement deposit address: {}",
                replacement_deposit_address
            );
        }
        AggregatorCommands::NewReplacementDeposit {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
            old_move_txid,
        } => {
            let mut old_move_txid = hex::decode(old_move_txid).expect("Failed to decode txid");
            old_move_txid.reverse();

            let mut deposit_outpoint_txid =
                hex::decode(deposit_outpoint_txid).expect("Failed to decode txid");
            deposit_outpoint_txid.reverse();

            let deposit = aggregator
                .new_deposit(Deposit {
                    deposit_outpoint: Some(Outpoint {
                        txid: Some(clementine_core::rpc::clementine::Txid {
                            txid: deposit_outpoint_txid.clone(),
                        }),
                        vout: deposit_outpoint_vout,
                    }),
                    deposit_data: Some(DepositData::ReplacementDeposit(ReplacementDeposit {
                        old_move_txid: Some(clementine::Txid {
                            txid: old_move_txid,
                        }),
                    })),
                })
                .await
                .expect("Failed to make a request");
            let deposit = aggregator
                .send_move_to_vault_tx(SendMoveTxRequest {
                    raw_tx: Some(deposit.into_inner()),
                    deposit_outpoint: Some(Outpoint {
                        txid: Some(clementine_core::rpc::clementine::Txid {
                            txid: deposit_outpoint_txid,
                        }),
                        vout: deposit_outpoint_vout,
                    }),
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
        AggregatorCommands::NewWithdrawal {
            withdrawal_id,
            input_signature,
            input_outpoint_txid,
            input_outpoint_vout,
            output_script_pubkey,
            output_amount,
        } => {
            println!("Processing withdrawal with id {}", withdrawal_id);

            let mut input_outpoint_txid_bytes =
                hex::decode(input_outpoint_txid).expect("Failed to decode input outpoint txid");
            input_outpoint_txid_bytes.reverse();

            let input_signature_bytes =
                hex::decode(input_signature).expect("Failed to decode input signature");

            let output_script_pubkey_bytes =
                hex::decode(output_script_pubkey).expect("Failed to decode output script pubkey");

            let params = clementine_core::rpc::clementine::WithdrawParams {
                withdrawal_id,
                input_signature: input_signature_bytes,
                input_outpoint: Some(Outpoint {
                    txid: Some(clementine_core::rpc::clementine::Txid {
                        txid: input_outpoint_txid_bytes,
                    }),
                    vout: input_outpoint_vout,
                }),
                output_script_pubkey: output_script_pubkey_bytes,
                output_amount,
            };

            let response = aggregator
                .withdraw(Request::new(params))
                .await
                .expect("Failed to make a request");

            let withdraw_responses = response.get_ref().withdraw_responses.clone();

            for (i, result) in withdraw_responses.iter().enumerate() {
                match &result.result {
                    Some(clementine_core::rpc::clementine::withdraw_result::Result::Success(_)) => {
                        println!("Operator {}: Withdrawal accepted", i);
                    }
                    Some(clementine_core::rpc::clementine::withdraw_result::Result::Error(
                        error,
                    )) => {
                        println!("Operator {}: Withdrawal failed: {}", i, error.error);
                    }
                    None => {
                        println!("Operator {}: Unknown result", i);
                    }
                }
            }
        }
        AggregatorCommands::Vergen => {
            let params = Empty {};
            let response = aggregator
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Vergen response:\n{}", response.into_inner().response);
        }
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
    }
}
