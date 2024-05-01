use clementine_core::{create_operator_server, create_verifier_server};
use std::env;
use std::str::FromStr;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

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
/// curl -X POST http://127.0.0.1:3434 -H "Content-Type: application/json" -d '{
///     "jsonrpc": "2.0",
///     "method": "operator_new_deposit",
///     "params": {
///         "start_utxo": "2964713fecf26d6eec7df4420bed1e09de1bdab2cacd24a1c8c0afd70c8a5371:3",
///         "return_address": "781990d7e2118cc361a93a6fcc54ce611d6df38168d6b1edfb556535f2200c4b",
///         "evm_address": "0101010101010101010101010101010101010101"
///     },
///     "id": 1
///     }'
/// ```
#[tokio::main]
async fn main() {
    initialize_logging();

    let verifier_configs = vec![
        "./configs/keys0.json",
        "./configs/keys1.json",
        "./configs/keys2.json",
        "./configs/keys3.json",
    ];
    let futures = verifier_configs
        .iter()
        .map(|config| create_verifier_server(None, None, Some(config.to_string())))
        .collect::<Vec<_>>();

    // Use `futures::future::try_join_all` to run all futures concurrently and wait for all to complete
    let results = futures::future::try_join_all(futures).await.unwrap();
    let verifier_endpoints = results
        .iter()
        .map(|(socket_addr, _)| format!("http://{}:{}/", socket_addr.ip(), socket_addr.port()))
        .collect::<Vec<_>>();

    let operator_config = "./configs/keys4.json";
    let (operator_socket_addr, operator_handle) = create_operator_server(
        verifier_endpoints,
        None,
        None,
        Some(operator_config.to_string()),
    )
    .await
    .unwrap();

    println!(
        "Operator running on {}",
        format!(
            "http://{}:{}/",
            operator_socket_addr.ip(),
            operator_socket_addr.port()
        )
    );

    operator_handle.stopped().await;
    for (_, handle) in results {
        handle.stopped().await;
    }
}
