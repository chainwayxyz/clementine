use std::sync::Arc;

use bitcoin::{OutPoint, Txid};
use bitcoincore_rpc::Auth;
use clementine_circuits::{HashType, PreimageType};
use errors::BridgeError;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::{Server, ServerHandle},
};
use operator::Operator;
use serde::{Deserialize, Serialize};
use traits::rpc::OperatorRpcServer;

use crate::{
    config::BridgeConfig, extended_rpc::ExtendedRpc, traits::rpc::VerifierRpcServer,
    verifier::Verifier,
};

pub mod actor;
pub mod cli;
pub mod config;
pub mod constants;
pub mod db;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
pub mod merkle;
pub mod mock_env;
pub mod operator;
pub mod script_builder;
pub mod traits;
pub mod transaction_builder;
pub mod user;
pub mod utils;
pub mod verifier;

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
pub type HashTree = Vec<Vec<HashType>>;
pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

/// Type alias for withdrawal payment, HashType is taproot script hash
pub type WithdrawalPayment = (Txid, HashType);

pub async fn create_verifier_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    tracing::debug!("Creating verifier server with config: {:?}", config);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );
    let verifier = Verifier::new(
        rpc,
        config.verifiers_public_keys.clone(),
        config.secret_key.clone(),
        config.clone(),
    )?;

    let server = Server::builder()
        .build(format!("{}:{}", config.host, config.port))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(verifier.into_rpc());
    Ok((addr, handle))
}

pub async fn create_operator_server(
    config: BridgeConfig,
    verifier_endpoints: Vec<String>,
    operator_port: u16,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );
    let mut verifiers: Vec<Arc<HttpClient>> = Vec::new();
    tracing::debug!("Verifiers: {:?}", verifier_endpoints);

    for i in 0..verifier_endpoints.len() {
        let verifier = HttpClientBuilder::default()
            .build(&verifier_endpoints[i])
            .unwrap();
        verifiers.push(verifier.into());
    }

    let operator = Operator::new(
        rpc.clone(),
        config.verifiers_public_keys.clone(),
        config.secret_key.clone(),
        verifiers,
        config.clone(),
    )
    .unwrap();

    let server = Server::builder()
        .build(format!("{}:{}", config.host, operator_port))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(operator.into_rpc());
    Ok((addr, handle))
}

pub async fn start_operator_and_verifiers(
    config: BridgeConfig,
) -> (
    HttpClient,
    ServerHandle,
    Vec<(std::net::SocketAddr, ServerHandle)>,
) {
    let mut all_secret_keys = config.all_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys are required for testing");
    });
    all_secret_keys.pop().unwrap(); // Remove the operator secret key

    let consec_ports = find_consecutive_idle_ports().await.unwrap();

    let futures = all_secret_keys
        .iter()
        .enumerate() // This adds the index to the iterator
        .map(|(i, sk)| {
            create_verifier_server(BridgeConfig {
                verifiers_public_keys: config.verifiers_public_keys.clone(),
                secret_key: *sk,
                port: consec_ports[i], // Use the index to calculate the port
                db_file_path: format!("{}{}", config.db_file_path.clone(), i.to_string()),
                ..config.clone()
            })
        })
        .collect::<Vec<_>>();

    // Use `futures::future::try_join_all` to run all futures concurrently and wait for all to complete
    let mut results = futures::future::try_join_all(futures).await.unwrap();
    let verifier_endpoints = results
        .iter()
        .map(|(socket_addr, _)| format!("http://{}:{}/", socket_addr.ip(), socket_addr.port()))
        .collect::<Vec<_>>();

    let (operator_socket_addr, operator_handle) =
        create_operator_server(config, verifier_endpoints, consec_ports[4])
            .await
            .unwrap();

    let operator_client = HttpClientBuilder::default()
        .build(&format!(
            "http://{}:{}/",
            operator_socket_addr.ip(),
            operator_socket_addr.port()
        ))
        .unwrap();
    results.push((operator_socket_addr, operator_handle.clone()));

    (operator_client, operator_handle, results)
}

use std::net::TcpListener;

pub async fn find_consecutive_idle_ports() -> Result<Vec<u16>, String> {
    let mut idle_ports = Vec::new();
    let mut current_port = 0;
    while current_port < 65535 {
        match TcpListener::bind(("0.0.0.0", current_port)) {
            Ok(_) => {
                idle_ports.push(current_port);
                current_port += 1;
                if idle_ports.len() == 5 {
                    break;
                }
            }
            Err(_) => {
                idle_ports.clear();
                current_port += 1;
            }
        }
    }
    if idle_ports.len() == 5 {
        Ok(idle_ports)
    } else {
        Err("No consecutive idle ports found".to_string())
    }
}
