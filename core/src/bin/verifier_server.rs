use bitcoin::{Address, OutPoint};
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::{constants::NUM_VERIFIERS, extended_rpc::ExtendedRpc, verifier::Verifier};
use clementine_core::{keys, EVMAddress};
use crypto_bigint::rand_core::OsRng;
use dotenv::dotenv;
use jsonrpsee::{server::Server, RpcModule};
use secp256k1::rand::{rngs::StdRng, SeedableRng};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use std::{env, net::SocketAddr};

#[derive(Deserialize)]
struct NewDepositParams {
    deposit_txid: String,
    deposit_vout: u32,
    user_return_xonly_pk: String,
    user_evm_address: String,
    operator_address: String,
}

/// main function to start verifier server
/// ```bash
/// curl -X POST http://localhost:3131 -H "Content-Type: application/json" -d '{
/// "jsonrpc": "2.0",
/// "method": "new_deposit",
/// "params": {
///     "deposit_txid": "30608915bfe45af7d922f05d3726b87208737d3d9088770a5627327ac79e6049",
///     "deposit_vout": 9,
///     "user_return_xonly_pk": "9a857208e280d56d008894e7088a4e059cccc28efed3cab1c06b0cfbe3df3526",
///     "user_evm_address": "0101010101010101010101010101010101010101",
///     "operator_address": "tb1qmfcjlvnwv5rzwu8dyj9akrcgu07a50geewsh5g"
/// },
/// "id": 1
/// }'
/// ```
#[tokio::main]
async fn main() {
    let rpc = ExtendedRpc::new();
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();
    let verifier = Verifier::new(rpc, all_xonly_pks, secret_key).unwrap();

    let port = env::var("PORT").unwrap_or_else(|_| "3131".to_string());

    let server = Server::builder()
        .build(format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let mut module = RpcModule::new(()); // Use appropriate context

    // Define your RPC methods
    module
        .register_async_method("new_deposit", move |params, _ctx| {
            println!("new_deposit called with params: {:?}", params);

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

            let operator_address = Address::from_str(&parsed_params.operator_address)
                .expect("Invalid operator_address")
                .assume_checked();

            let verifier_clone = verifier.clone(); // Assuming Verifier is Clone

            async move {
                // Call the appropriate method on the Verifier instance
                let deposit_signatures = verifier_clone
                    .new_deposit(
                        start_utxo,
                        &return_address,
                        0,
                        &evm_address,
                        &operator_address,
                    )
                    .await
                    .unwrap();

                let json_result = serde_json::to_string(&deposit_signatures);
                match json_result {
                    Ok(json) => Ok(json), // Return the JSON string
                    Err(e) => Err(format!("Error serializing response: {}", e)),
                }
                .unwrap()
            }
        })
        .unwrap();
    let handle = server.start(module);
    println!("Listening on {:?}", handle);

    // In this example we don't care about doing shutdown so let's it run forever.
    // You may use the `ServerHandle` to shut it down or manage it yourself.
    tokio::spawn(handle.stopped());
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
