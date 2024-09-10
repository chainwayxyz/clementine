use clementine_core::{
    musig2::AggregateFromPublicKeys, servers::create_verifiers_and_operators,
    utils::get_configuration_for_binaries,
};

#[tokio::main]
async fn main() {
    let (config, _) = get_configuration_for_binaries();

    let (verifier_clients, operator_clients, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    println!(
        "OPERATOR_URLS={}",
        operator_clients
            .iter()
            .map(|(_, _, addr)| format!("http://127.0.0.1:{}", addr.port()))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "VERIFIER_URLS={}",
        verifier_clients
            .iter()
            .map(|(_, _, addr)| format!("http://127.0.0.1:{}", addr.port()))
            .collect::<Vec<_>>()
            .join(",")
    );
    let xonly = secp256k1::XOnlyPublicKey::from_musig2_pks(
        config.verifier.verifiers_public_keys,
        None,
        false,
    );
    println!(
        "AGGREGATOR_URL={}",
        format!("http://127.0.0.1:{}", aggregator.2.port())
    );
    println!("VERIFIER_PKS={}", xonly.to_string());

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
