//! # Citrea Requests
//!
//! This module contains the functions to build the requests for interacting
//! with the Citrea smart contracts.
//!
//! Function selectors are defined in:
//! https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80

use crate::errors::BridgeError;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

const CITREA_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

macro_rules! encode_btc_params {
    ($params:expr) => {
        $params
            .iter()
            .map(|param| {
                let mut raw = Vec::new();
                param
                    .consensus_encode(&mut raw)
                    .map_err(|e| BridgeError::Error(format!("Can't encode param: {}", e)))?;

                Ok::<Vec<u8>, BridgeError>(raw)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>()
    };

    ($params:expr, $inner:tt) => {
        $params
            .iter()
            .map(|param| {
                let mut raw = Vec::new();
                param
                    .$inner
                    .consensus_encode(&mut raw)
                    .map_err(|e| BridgeError::Error(format!("Can't encode param: {}", e)))?;

                Ok::<Vec<u8>, BridgeError>(raw)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>()
    };
}

pub async fn deposit(
    client: HttpClient,
    transaction: Transaction,
    flag: u16,
    merkle_proof: Vec<u8>, // intermediate_nodes
    block_height: u32,
    index: u32,
) -> Result<(), BridgeError> {
    let version: u32 = transaction.version.0 as u32;
    let vin: Vec<u8> = encode_btc_params!(transaction.input);
    let vout: Vec<u8> = encode_btc_params!(transaction.output);
    let witness: Vec<u8> = encode_btc_params!(transaction.input, witness);
    let locktime: u32 = transaction.lock_time.to_consensus_u32();

    let message = {
        let mut message = Vec::new();
        message.extend_from_slice(&version.to_be_bytes());
        message.extend_from_slice(&flag.to_be_bytes());
        message.extend_from_slice(&vin.len().to_be_bytes());
        message.extend_from_slice(&vin);
        message.extend_from_slice(&vout.len().to_be_bytes());
        message.extend_from_slice(&vout);
        message.extend_from_slice(&witness.len().to_be_bytes());
        message.extend_from_slice(&witness);
        message.extend_from_slice(&locktime.to_be_bytes());
        message.extend_from_slice(&merkle_proof);
        message.extend_from_slice(&[0u8; 28]); // First 28 bytes of block height
        message.extend_from_slice(&block_height.to_be_bytes());
        message.extend_from_slice(&[0u8; 28]); // First 28 bytes of index
        message.extend_from_slice(&index.to_be_bytes());
        message
    };

    let params = rpc_params![
        json!({
            "to": CITREA_ADDRESS,
            "data": format!("0xdd95c7c6{}",
            hex::encode(message)),
        }),
        "latest"
    ];

    let response: String = client.request("eth_call", params).await?;

    // TODO: should return a bool but dont know the format of the response
    tracing::info!("Deposit response: {}", response);

    Ok(())
}

/// TODO: withdrawal_index is u256, convert it to [u8; 32]
pub async fn withdrawal_utxos(
    client: HttpClient,
    withdrawal_index: u32,
) -> Result<Txid, BridgeError> {
    let params = rpc_params![
        json!({
            "to": CITREA_ADDRESS,
            "data": format!("0x471ba1e300000000000000000000000000000000000000000000000000000000{}",
            hex::encode(withdrawal_index.to_be_bytes())),
        }),
        "latest"
    ];
    let response: String = client.request("eth_call", params).await?;

    let txid_str_slice = &response[2..66];
    let txid = hex::decode(txid_str_slice).map_err(|e| BridgeError::Error(e.to_string()))?;
    // txid.reverse(); // TODO: we should need to reverse this, test this with declareWithdrawalFiller

    Ok(Txid::from_slice(&txid)?)
}
