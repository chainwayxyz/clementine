//! # Citrea Requests
//!
//! This module contains the functions to build the requests for interacting
//! with the Citrea smart contracts.
//!
//! Function selectors are defined in:
//! https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80

use crate::builder::citrea::parameter::get_deposit_params;
use crate::errors::BridgeError;
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, Txid};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

const CITREA_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

pub async fn script_prefix(client: HttpClient) -> Result<(), BridgeError> {
    let params = rpc_params![
        json!({
            "to": CITREA_ADDRESS,
            "data": "0xa41c5cf3"
        }),
        "latest"
    ];

    let response: String = client.request("eth_call", params).await?;
    tracing::error!("eeee {:?}", response);

    // let decoded_hex = hex::decode(&response[2..]).map_err(|e| BridgeError::Error(e.to_string()))?;

    // if decoded_hex
    //     .last()
    //     .ok_or(BridgeError::Error("Empty response".to_string()))?
    //     != &1u8
    // {
    //     return Err(BridgeError::Error("Contract not initialized".to_string()));
    // }

    Ok(())
}
pub async fn get_block_nu(client: HttpClient) -> Result<u32, BridgeError> {
    let params = rpc_params![
        json!({
            "to": "0x3100000000000000000000000000000000000001",
            "data": "0x57e871e7"
        }),
        "latest"
    ];

    let response: String = client.request("eth_call", params).await?;
    tracing::error!("eee {:?}", response);

    let decoded_hex = hex::decode(&response[2..]).map_err(|e| BridgeError::Error(e.to_string()))?;
    let block_number = decoded_hex
        .iter()
        .rev()
        .take(4)
        .rev()
        .fold(0u32, |acc, &byte| acc << 8 | byte as u32);
    tracing::error!("block_number {:?}", block_number);

    Ok(block_number)
}
pub async fn depositAmount(client: HttpClient) -> Result<u32, BridgeError> {
    let params = rpc_params![
        "0101010101010101010101010101010101010101",
        "latest"
    ];

    let response: String = client.request("eth_getBalance", params).await?;
    tracing::error!("eeeb {:?}", response);

    // let decoded_hex = hex::decode(&response[2..]).map_err(|e| BridgeError::Error(e.to_string()))?;
    // let block_number = decoded_hex
    //     .iter()
    //     .rev()
    //     .take(4)
    //     .rev()
    //     .fold(0u32, |acc, &byte| acc << 8 | byte as u32);
    // tracing::error!("block_number {:?}", block_number);

    Ok(0x45)
}


pub async fn deposit(
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let params = get_deposit_params(transaction, block, block_height, txid)?;

    let response: () = client
        .request(
            "citrea_sendRawDepositTransaction",
            rpc_params!(hex::encode(params)),
        )
        .await?;

    // TODO: should return a bool but dont know the format of the response
    tracing::info!("Deposit response: {:?}", response);

    Ok(())
}

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
