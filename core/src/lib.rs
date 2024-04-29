use std::sync::Arc;

use bitcoin::{OutPoint, Txid};
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
pub mod config;
pub mod constants;
pub mod db;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
pub mod keys;
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
    port: Option<u16>,
    keys_file: Option<String>,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    let config = BridgeConfig::new()?;
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_auth.clone(),
    );
    let keys_file = match keys_file {
        Some(file) => file,
        None => panic!("keys file is required"), // TODO: Take this from config
    };
    let (secret_key, all_xonly_pks) = keys::read_file(keys_file.to_string())?;
    let verifier = Verifier::new(rpc, all_xonly_pks, secret_key, config.clone())?;

    let server = Server::builder()
        .build(format!("127.0.0.1:{}", port.or_else(|| Some(0)).unwrap()))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(verifier.into_rpc());
    Ok((addr, handle))
}

pub async fn create_operator_server(
    verifier_endpoints: Vec<String>,
    port: Option<u16>,
    keys_file: Option<String>,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    let config = BridgeConfig::new()?;
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_auth.clone(),
    );
    let keys_file = match keys_file {
        Some(file) => file,
        None => panic!("keys file is required"), // TODO: Take this from config
    };
    let (secret_key, all_xonly_pks) = keys::read_file(keys_file.to_string())?;

    let mut verifiers: Vec<Arc<HttpClient>> = Vec::new();
    for i in 0..verifier_endpoints.len() {
        let verifier = HttpClientBuilder::default()
            .build(&verifier_endpoints[i])
            .unwrap();
        verifiers.push(verifier.into());
    }

    let operator = Operator::new(
        rpc.clone(),
        all_xonly_pks.clone(),
        secret_key,
        verifiers,
        config.clone(),
    )
    .unwrap();

    let server = Server::builder()
        .build(format!("127.0.0.1:{}", port.or_else(|| Some(0)).unwrap()))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(operator.into_rpc());
    Ok((addr, handle))
}

pub async fn start_operator_and_verifiers() -> (
    HttpClient,
    ServerHandle,
    Vec<(std::net::SocketAddr, ServerHandle)>,
) {
    let verifier_configs = vec![
        "./configs/keys0.json",
        "./configs/keys1.json",
        "./configs/keys2.json",
        "./configs/keys3.json",
    ];
    let futures = verifier_configs
        .iter()
        .map(|config| create_verifier_server(None, Some(config.to_string())))
        .collect::<Vec<_>>();

    // Use `futures::future::try_join_all` to run all futures concurrently and wait for all to complete
    let mut results = futures::future::try_join_all(futures).await.unwrap();
    let verifier_endpoints = results
        .iter()
        .map(|(socket_addr, _)| format!("http://{}:{}/", socket_addr.ip(), socket_addr.port()))
        .collect::<Vec<_>>();

    let operator_config = "./configs/keys4.json";
    let (operator_socket_addr, operator_handle) =
        create_operator_server(verifier_endpoints, None, Some(operator_config.to_string()))
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
