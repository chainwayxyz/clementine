use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{
    create_operator_server, create_verifier_server, traits::rpc::OperatorRpcClient,
};
use clementine_core::{keys, EVMAddress};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::server::ServerHandle;

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
    let results = futures::future::try_join_all(futures).await.unwrap();
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

    (operator_client, operator_handle, results)
}

#[tokio::test]
async fn test_flow() {
    let (operator_client, operator_handler, results) = start_operator_and_verifiers().await;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = BridgeConfig::new().unwrap();
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();
    let tx_builder = TransactionBuilder::new(all_xonly_pks.clone(), config.clone());

    let (xonly_pk, _) = secret_key.public_key(&secp).x_only_public_key();
    let evm_address: EVMAddress = EVMAddress([1u8; 20]);

    let (deposit_address, _) = tx_builder
        .generate_deposit_address(&xonly_pk, &evm_address, BRIDGE_AMOUNT_SATS)
        .unwrap();

    println!("EVM Address: {:?}", hex::encode(evm_address.0));
    println!("User: {:?}", xonly_pk.to_string());
    println!("Deposit address: {:?}", deposit_address);

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_auth.clone(),
    );

    let deposit_utxo = rpc
        .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)
        .unwrap();

    println!("Deposit UTXO: {:?}", deposit_utxo);
    rpc.mine_blocks(18).unwrap();

    let output = operator_client
        .new_deposit_rpc(deposit_utxo, xonly_pk, evm_address)
        .await
        .unwrap();

    println!("Output: {:?}", output);

    let op_res = operator_handler.is_stopped();
    let ver_res = results
        .iter()
        .all(|(_, verifier_handler)| verifier_handler.is_stopped());
    assert!(!(op_res || ver_res));
    let op_res = operator_handler.stop().unwrap();
    let mut ver_res = Vec::new();
    for (_, verifier_handler) in results {
        ver_res.push(verifier_handler.stop().unwrap());
    }
    println!("Operator stopped: {:?}", op_res);
    for (i, res) in ver_res.iter().enumerate() {
        println!("Verifier {} stopped: {:?}", i, res);
    }
    println!("All servers stopped");
}
