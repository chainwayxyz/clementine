use bitcoin::{Address, OutPoint};
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::EVMAddress;
use clementine_core::{constants::NUM_VERIFIERS, extended_rpc::ExtendedRpc, verifier::Verifier};
use crypto_bigint::rand_core::OsRng;
use dotenv::dotenv;
use jsonrpsee::{server::Server, RpcModule};
use secp256k1::rand::{rngs::StdRng, SeedableRng};
use secp256k1::XOnlyPublicKey;
use serde::Deserialize;
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
///     "deposit_txid": "4a993d208d3faae29591a92d6e09fcab58d0a74422d45c784ec8f9b6f8e90f98",
///     "deposit_vout": 6,
///     "user_return_xonly_pk": "9a857208e280d56d008894e7088a4e059cccc28efed3cab1c06b0cfbe3df3526",
///     "user_evm_address": "0000000000000000000000000000000000000000",
///     "operator_address": "tb1qmfcjlvnwv5rzwu8dyj9akrcgu07a50geewsh5g"
/// },
/// "id": 1
/// }'
/// ```
#[tokio::main]
async fn main() {
    let rpc = ExtendedRpc::new();

    let secp = bitcoin::secp256k1::Secp256k1::new();

    let seed: [u8; 32] = [0u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed);
    let rng = &mut OsRng;

    let (all_sks, all_xonly_pks): (Vec<_>, Vec<_>) = (0..NUM_VERIFIERS + 1)
        .map(|_| {
            let (sk, pk) = secp.generate_keypair(rng);
            (sk, XOnlyPublicKey::from(pk))
        })
        .unzip();

    // Initialization of Verifier, RPC, etc. goes here

    let server = Server::builder()
        .build("127.0.0.1:3131".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let mut module = RpcModule::new(()); // Use appropriate context

    let verifier = Verifier::new(rpc, all_xonly_pks, all_sks[0]).unwrap();

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

            let operator_address = Address::from_str(&parsed_params.operator_address)
                .expect("Invalid operator_address")
                .assume_checked();

            let verifier_clone = verifier.clone(); // Assuming Verifier is Clone
            async move {
                // Call the appropriate method on the Verifier instance
                verifier_clone
                    .new_deposit(
                        start_utxo,
                        &return_address,
                        0,
                        &evm_address,
                        &operator_address,
                    )
                    .await
                    .unwrap();
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
