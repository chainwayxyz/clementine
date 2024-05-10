use std::sync::Arc;

use bitcoin::{OutPoint, Txid};
use bitcoincore_rpc::Auth;
use clementine_circuits::{HashType, PreimageType};
use errors::BridgeError;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder},
    server::{Server, ServerHandle},
};
use operator::Operator;
use serde::{Deserialize, Serialize};
use traits::rpc::OperatorRpcServer;

use crate::{
    config::BridgeConfig, extended_rpc::ExtendedRpc, traits::rpc::VerifierRpcServer,
    verifier::Verifier,
};

pub mod actor;
pub mod cli;
pub mod config;
pub mod constants;
pub mod db;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
pub mod merkle;
pub mod mock_env;
pub mod operator;
pub mod script_builder;
pub mod test_common;
pub mod traits;
pub mod transaction_builder;
pub mod user;
pub mod utils;
pub mod verifier;

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
pub type HashTree = Vec<Vec<HashType>>;
pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

/// Type alias for withdrawal payment, HashType is taproot script hash
pub type WithdrawalPayment = (Txid, HashType);

pub async fn create_verifier_server(
    config: BridgeConfig,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    tracing::debug!("Creating verifier server with config: {:?}", config);
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
    .await?;

    let server = Server::builder()
        .build(format!("{}:{}", config.host, 0))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(verifier.into_rpc());
    Ok((addr, handle))
}

pub async fn create_operator_server(
    config: BridgeConfig,
    verifier_endpoints: Vec<String>,
) -> Result<(std::net::SocketAddr, ServerHandle), BridgeError> {
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );
    let mut verifiers: Vec<Arc<HttpClient>> = Vec::new();
    tracing::debug!("Verifiers: {:?}", verifier_endpoints);

    for i in 0..verifier_endpoints.len() {
        let verifier = HttpClientBuilder::default()
            .build(&verifier_endpoints[i])
            .unwrap();
        verifiers.push(verifier.into());
    }

    let operator = Operator::new(
        rpc.clone(),
        config.verifiers_public_keys.clone(),
        config.secret_key.clone(),
        verifiers,
        config.clone(),
    )
    .await
    .unwrap();

    let server = Server::builder()
        .build(format!("{}:{}", config.host, 0))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(operator.into_rpc());
    tracing::debug!("Operator server started at: {}", addr);
    Ok((addr, handle))
}

pub async fn start_operator_and_verifiers(
    config: BridgeConfig,
) -> (
    HttpClient,
    ServerHandle,
    Vec<(std::net::SocketAddr, ServerHandle)>,
) {
    let mut all_secret_keys = config.all_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys are required for testing");
    });
    all_secret_keys.pop().unwrap(); // Remove the operator secret key

    let futures = all_secret_keys
        .iter()
        .enumerate() // This adds the index to the iterator
        .map(|(i, sk)| {
            create_verifier_server(BridgeConfig {
                verifiers_public_keys: config.verifiers_public_keys.clone(),
                secret_key: *sk,
                port: 0, // Use the index to calculate the port
                db_name: config.db_name.clone() + &i.to_string(),
                ..config.clone()
            })
        })
        .collect::<Vec<_>>();

    // Use `futures::future::try_join_all` to run all futures concurrently and wait for all to complete
    let mut results = futures::future::try_join_all(futures).await.unwrap();
    let verifier_endpoints = results
        .iter()
        .map(|(socket_addr, _)| format!("http://{}:{}/", socket_addr.ip(), socket_addr.port()))
        .collect::<Vec<_>>();

    let (operator_socket_addr, operator_handle) =
        create_operator_server(config, verifier_endpoints)
            .await
            .unwrap();

    let operator_client = HttpClientBuilder::default()
        .build(&format!(
            "http://{}:{}/",
            operator_socket_addr.ip(),
            operator_socket_addr.port()
        ))
        .unwrap();
    results.push((operator_socket_addr, operator_handle.clone()));

    (operator_client, operator_handle, results)
}

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeTuple, Serializer};

#[derive(Clone, Debug)]
pub struct ByteArray66(pub [u8; 66]);

impl Serialize for ByteArray66 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ByteArray66 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArray66Visitor;

        impl<'de> Visitor<'de> for ByteArray66Visitor {
            type Value = ByteArray66;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 66")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<ByteArray66, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut array = [0u8; 66];
                for (i, byte) in array.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(ByteArray66(array))
            }
        }

        deserializer.deserialize_tuple(66, ByteArray66Visitor)
    }
}
