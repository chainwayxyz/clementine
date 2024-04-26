use bitcoin::OutPoint;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::operator::Operator;
use clementine_core::traits::verifier::{OperatorRpcServer, VerifierRpcServer};
use clementine_core::verifier::Verifier;
use clementine_core::{keys, EVMAddress};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::{server::Server, RpcModule};
use secp256k1::XOnlyPublicKey;
use serde::Deserialize;
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, net::SocketAddr};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Deserialize)]
struct NewDepositParams {
    deposit_txid: String,
    deposit_vout: u32,
    user_return_xonly_pk: String,
    user_evm_address: String,
}

/// Default initialization of logging
pub fn initialize_logging() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_str(
                &env::var("RUST_LOG").unwrap_or_else(|_| "debug,bitcoincore_rpc=info".to_string()),
            )
            .unwrap(),
        )
        .init();
}

/// main function to start operator server
/// ```bash
/// curl -X POST http://127.0.0.1:54486 -H "Content-Type: application/json" -d '{
/// "jsonrpc": "2.0",
/// "method": "new_deposit",
/// "params": {
///     "deposit_txid": "4f4406c2e273f88b095e3155cf766e45c3468c56fecabfa9fe7c0de7f75cc247",
///     "deposit_vout": 0,
///     "user_return_xonly_pk": "52a208d3a465d9670713237766bcff00bd14156db5d631f659b3815099503549",
///     "user_evm_address": "6D4BF3D9cbA4d3eb37db2feBaaDB5E12f8e49d3E"
/// },
/// "id": 1
/// }'
/// ```
#[tokio::main]
async fn main() {
    initialize_logging();

    let configs = vec![
        ("43801", "../configs/keys0.json"),
        ("34521", "../configs/keys1.json"),
        ("43379", "../configs/keys2.json"),
        ("35727", "../configs/keys3.json"),
    ];

    let mut handles = vec![];

    for (port, keys_file) in configs {
        let config = BridgeConfig::new().unwrap();
        let rpc = ExtendedRpc::new(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_auth.clone(),
        );
        let (secret_key, all_xonly_pks) = keys::read_file(keys_file.to_string()).unwrap();
        let verifier = Verifier::new(rpc, all_xonly_pks, secret_key, config.clone()).unwrap();

        let server = Server::builder()
            .build(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        println!("Listening on {:?}", addr);
        let handle = server.start(verifier.into_rpc());

        handles.push(tokio::spawn(handle.stopped()));
    }

    let config = BridgeConfig::new().unwrap();
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_auth.clone(),
    );
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();

    let verifier_endpoints = vec![
        "http://127.0.0.1:3030".to_string(),
        "http://127.0.0.1:3131".to_string(),
        "http://127.0.0.1:3232".to_string(),
        "http://127.0.0.1:3333".to_string(),
    ];

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
        .build(format!("127.0.0.1:3434"))
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    println!("Listening on {:?}", addr);
    let handle = server.start(operator.into_rpc());
    handles.push(tokio::spawn(handle.stopped()));
    for handle in handles {
        handle.await.unwrap();
    }
}
