//! # Citrea Requests
//!
//! This module contains the functions to build the requests for interacting
//! with the Citrea smart contracts.
//!
//! Function selectors are defined in:
//! https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80

use crate::builder::citrea::parameter::{get_deposit_block_params, get_deposit_transaction_params};
use crate::errors::BridgeError;
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, Txid};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

const CITREA_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

pub async fn deposit(
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let encoded_transaction = get_deposit_transaction_params(transaction)?;
    let encoded_block_info = get_deposit_block_params(block, block_height, txid)?;

    let message = {
        let mut message = Vec::new();
        message.extend_from_slice(&encoded_transaction);
        message.extend_from_slice(&encoded_block_info);
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
