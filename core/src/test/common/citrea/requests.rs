use crate::citrea::LIGHT_CLIENT_ADDRESS;
use crate::errors::BridgeError;
use crate::test::common::citrea::parameters::get_transaction_params;
use crate::EVMAddress;
use alloy::sol_types::SolValue;
use bitcoin::{Block, Transaction};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

pub async fn block_number(client: &HttpClient) -> Result<u32, BridgeError> {
    let params = rpc_params![
        json!({
            "to": LIGHT_CLIENT_ADDRESS,
            "data": "0x57e871e7"
        }),
        "latest"
    ];

    let response: String = client.request("eth_call", params).await?;

    let decoded_hex = hex::decode(&response[2..]).map_err(|e| BridgeError::Error(e.to_string()))?;
    let block_number = decoded_hex
        .iter()
        .rev()
        .take(4)
        .rev()
        .fold(0u32, |acc, &byte| (acc << 8) | byte as u32);

    Ok(block_number)
}

pub async fn eth_get_balance(
    client: HttpClient,
    evm_address: EVMAddress,
) -> Result<u128, BridgeError> {
    let params = rpc_params![evm_address.0, "latest"];

    let response: String = client.request("eth_getBalance", params).await?;
    let ret = u128::from_str_radix(&response[2..], 16)
        .map_err(|e| BridgeError::Error(format!("Can't convert hex to int: {}", e)))?;

    Ok(ret)
}

/// Deposits a transaction to Citrea. This function is different from `contract.deposit` because it
/// won't directly talk with EVM but with Citrea. So that authorization can be done (Citrea will
/// block this call if it isn't an operator).
pub async fn deposit(
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let params = get_transaction_params(transaction, block, block_height, txid)?;

    let _response: () = client
        .request(
            "citrea_sendRawDepositTransaction",
            rpc_params!(hex::encode(params.abi_encode())),
        )
        .await?;

    Ok(())
}
