use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint};
use clementine_core::config::BridgeConfig;
use clementine_core::errors::BridgeError;
use clementine_core::operator::DepositPresigns;
use clementine_core::traits::rpc::{VerifierRpcClient, VerifierRpcServer};
use clementine_core::{extended_rpc::ExtendedRpc, verifier::Verifier};
use clementine_core::{keys, EVMAddress};
use jsonrpsee::core::async_trait;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{server::Server, RpcModule};
use secp256k1::XOnlyPublicKey;
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::str::FromStr;

// #[rpc(client, server, namespace = "verifier")]
// pub trait VerifierRpc {
//     #[method(name = "new_deposit")]
//     async fn new_deposit_rpc(
//         &self,
//         start_utxo: OutPoint,
//         return_address: XOnlyPublicKey,
//         deposit_index: u32,
//         evm_address: EVMAddress,
//         operator_address: Address<NetworkUnchecked>,
//     ) -> Result<DepositPresigns, BridgeError>;
// }

// #[async_trait]
// impl VerifierRpcServer for Verifier {
//     async fn new_deposit_rpc(
//         &self,
//         start_utxo: OutPoint,
//         return_address: XOnlyPublicKey,
//         deposit_index: u32,
//         evm_address: EVMAddress,
//         operator_address: Address<NetworkUnchecked>,
//     ) -> Result<DepositPresigns, BridgeError> {
//         let operator_address = operator_address.assume_checked();
//         self.new_deposit(start_utxo, &return_address, deposit_index, &evm_address, &operator_address).await
//     }
// }

#[tokio::main]
async fn main() {
    // let config = BridgeConfig::new().unwrap();
    // let rpc = ExtendedRpc::new(
    //     config.bitcoin_rpc_url.clone(),
    //     config.bitcoin_rpc_auth.clone(),
    // );
    // let keys_file = "configs/keys0.json";
    // let (secret_key, all_xonly_pks) = keys::read_file(keys_file.to_string()).unwrap();
    // let verifier = Verifier::new(rpc, all_xonly_pks, secret_key, config.clone()).unwrap();

    // let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    // let addr = server.local_addr().unwrap();
    // println!("Listening on {:?}", addr);
    // let handle = server.start(verifier.into_rpc());
    // println!("Listening on {:?}", addr);
    // handle.stopped().await;

    // let url = format!("http://127.0.0.1:{}", addr.port());
    // let x: jsonrpsee::http_client::HttpClient = HttpClientBuilder::default().build(&url).unwrap();

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

        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        println!("Listening on {:?}", addr);
        let handle = server.start(verifier.into_rpc());

        handles.push(tokio::spawn(handle.stopped()));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
