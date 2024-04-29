use bitcoin::OutPoint;
use bitcoincore_rpc::Auth;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::operator::Operator;
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::verifier::VerifierClient;
use clementine_core::{keys, EVMAddress};
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
/// curl -X POST http://localhost:3434 -H "Content-Type: application/json" -d '{
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
    let config = BridgeConfig::new();
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();

    let verifier_endpoints = vec![
        "http://127.0.0.1:3030".to_string(),
        "http://127.0.0.1:3131".to_string(),
        "http://127.0.0.1:3232".to_string(),
        "http://127.0.0.1:3333".to_string(),
    ];

    let mut verifiers: Vec<Arc<dyn VerifierConnector>> = Vec::new();
    for i in 0..verifier_endpoints.len() {
        let verifier = VerifierClient::new(verifier_endpoints[i].clone());
        verifiers.push(Arc::new(verifier) as Arc<dyn VerifierConnector>);
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
        .build("127.0.0.1:3434".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let mut module = RpcModule::new(()); // Use appropriate context

    println!("operator server is being created");
    // Define your RPC methods
    module
        .register_async_method("new_deposit", move |params, _ctx| {
            println!("new_deposit called");

            let parsed_params: NewDepositParams =
                match serde_json::from_value(params.parse().unwrap()).unwrap() {
                    Value::Object(map) => serde_json::from_value(Value::Object(map)).unwrap(),
                    _ => panic!("Invalid params"),
                };

            let start_utxo = OutPoint::new(
                bitcoin::Txid::from_str(&parsed_params.deposit_txid).expect("Invalid Txid"),
                parsed_params.deposit_vout,
            );

            let return_address = XOnlyPublicKey::from_slice(
                &hex::decode(&parsed_params.user_return_xonly_pk)
                    .expect("Invalid hex for XOnlyPublicKey"),
            )
            .expect("Invalid XOnlyPublicKey");

            let evm_address: EVMAddress = hex::decode(&parsed_params.user_evm_address)
                .expect("Invalid EVMAddress")
                .try_into()
                .expect("Invalid EVMAddress");

            let mut operator_clone = operator.clone(); // Assuming Verifier is Clone
            async move {
                // Call the appropriate method on the Verifier instance
                let move_utxo = operator_clone
                    .new_deposit(start_utxo, &return_address, &evm_address)
                    .await
                    .unwrap();
                println!("move_utxo: {:?}", move_utxo);
                serde_json::to_string(&move_utxo).unwrap()
            }
        })
        .unwrap();
    let handle = server.start(module);
    println!("Listening on {:?}", handle);

    handle.stopped().await;
}
