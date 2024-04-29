use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{keys, start_operator_and_verifiers, EVMAddress};

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
