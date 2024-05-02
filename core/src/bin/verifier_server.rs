use bitcoin::{Address, OutPoint};
use bitcoincore_rpc::Auth;
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::{cli, EVMAddress};
use clementine_core::{extended_rpc::ExtendedRpc, verifier::Verifier};
use jsonrpsee::{server::Server, RpcModule};
use secp256k1::XOnlyPublicKey;
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Deserialize, Clone)]
struct NewDepositParams {
    deposit_txid: String,
    deposit_vout: u32,
    user_return_xonly_pk: String,
    user_evm_address: String,
    operator_address: String,
}

#[tokio::main]
async fn main() {
    let configs = vec![
        ("3030", "configs/keys0.json"),
        ("3131", "configs/keys1.json"),
        ("3232", "configs/keys2.json"),
        ("3333", "configs/keys3.json"),
    ];

    let mut handles = vec![];

    for (port, _keys_file) in configs {
        let handle = tokio::spawn(async move {
            let config = cli::get_configuration();
            let rpc = ExtendedRpc::new(
                config.bitcoin_rpc_url.clone(),
                Auth::UserPass(
                    config.bitcoin_rpc_user.clone(),
                    config.bitcoin_rpc_password.clone(),
                ),
            );
            let verifier = Verifier::new(
                rpc,
                config.verifiers_public_keys.clone(),
                config.secret_key.clone(),
                config.clone(),
            )
            .unwrap();

            let server = Server::builder()
                .build(format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap())
                .await
                .unwrap();
            let mut module = RpcModule::new(()); // Use appropriate context
            println!("Starting server: {:?}", server);

            // Define your RPC methods
            module
                .register_async_method("new_deposit", move |params, _ctx| {
                    println!("new_deposit called with params: {:?}", params);

                    let parsed_params: NewDepositParams =
                        match serde_json::from_value(params.parse().unwrap()).unwrap() {
                            Value::Object(map) => {
                                serde_json::from_value(Value::Object(map)).unwrap()
                            }
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
                        serde_json::to_string(&deposit_signatures).unwrap()
                    }
                })
                .unwrap();
            let handle = server.start(module);
            println!("Listening on {:?}", handle);

            // In this example we don't care about doing shutdown so let's it run forever.
            // You may use the `ServerHandle` to shut it down or manage it yourself.
            handle.stopped().await;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
