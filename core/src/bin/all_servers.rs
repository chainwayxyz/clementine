use clementine_core::{cli, extended_rpc::ExtendedRpc, servers::create_verifiers_and_operators};

#[tokio::main]
async fn main() {
    let config = cli::get_configuration();
    let _rpc = ExtendedRpc::<bitcoincore_rpc::Client>::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    let (verifier_clients, operator_clients, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    println!(
        "OPERATOR_URLS={}",
        operator_clients
            .iter()
            .map(|(_, _, addr)| format!("http://localhost:{}", addr.port()))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "VERIFIER_URLS={}",
        verifier_clients
            .iter()
            .map(|(_, _, addr)| format!("http://localhost:{}", addr.port()))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("AGGREGATOR_URL={}", aggregator.2);

    // Stop all servers
    for (_, handle, _) in operator_clients {
        handle.clone().stopped().await;
    }

    for (_, handle, _) in verifier_clients {
        handle.clone().stopped().await;
    }

    aggregator.1.stopped().await;

    println!("All servers stopped");
}
