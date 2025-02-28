use crate::errors::BridgeError;
use crate::test::common::citrea::parameters::get_deposit_params;
use crate::EVMAddress;
use alloy::consensus::constants::{ETH_TO_WEI, GWEI_TO_WEI};
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, Txid};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

const LIGHT_CLIENT_ADDRESS: &str = "0x3100000000000000000000000000000000000001";
const CITREA_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

pub async fn script_prefix(client: HttpClient) -> Result<String, BridgeError> {
    let params = rpc_params![
        json!({
            "to": CITREA_ADDRESS,
            "data": "0xa41c5cf3"
        }),
        "latest"
    ];

    let response: String = client.request("eth_call", params).await?;
    tracing::error!("eeee {:?}", response);

    Ok(response)
}

pub async fn block_number(client: HttpClient) -> Result<u32, BridgeError> {
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

pub async fn eth_get_transaction_count(
    client: HttpClient,
    evm_address: EVMAddress,
) -> Result<u128, BridgeError> {
    let params = rpc_params![evm_address.0, "latest"];

    let response: String = client.request("eth_getTransactionCount", params).await?;
    let ret = u128::from_str_radix(&response[2..], 16)
        .map_err(|e| BridgeError::Error(format!("Can't convert hex to int: {}", e)))?;

    Ok(ret)
}

pub async fn get_withdrawal_count(client: HttpClient) -> Result<u32, BridgeError> {
    let params = rpc_params![
        json!({
            "to": CITREA_ADDRESS,
            "data": "0x781952a8"
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

pub async fn deposit(
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let params = get_deposit_params(transaction, block, block_height, txid)?;

    let _response: () = client
        .request(
            "citrea_sendRawDepositTransaction",
            rpc_params!(hex::encode(params)),
        )
        .await?;

    Ok(())
}

pub async fn declare_withdraw_filler(
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
    input_index: u32,
    withdrawal_index: u32,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let params = get_deposit_params(transaction, block, block_height, txid)?;

    let params = rpc_params![
        json!({
            "to": CITREA_ADDRESS,
            "data": format!("0x74ab4a83{}0000000000000000000000000000{}0000000000000000000000000000{}", hex::encode(params), hex::encode(input_index.to_be_bytes()), hex::encode(withdrawal_index.to_be_bytes())),
        }),
        "latest"
    ];
    let response: String = client.request("eth_call", params).await?;

    tracing::info!("declare_withdraw_filler response: {:?}", response);

    Ok(())
}

pub async fn withdraw(
    client: HttpClient,
    from_address: &str,
    withdrawal_txid: Txid,
    withdrawal_index: u32,
    withdrawal_amount: u64,
    gas: u64,
    gas_price: u128,
    nonce: u128,
) -> Result<(), BridgeError> {
    let withdrawal_amount = withdrawal_amount as u128 * ETH_TO_WEI;
    let gas_price = gas_price * GWEI_TO_WEI as u128;

    let params = rpc_params![
        json!({
            "from": from_address,
            "to": CITREA_ADDRESS,
            "data": format!("0x8786dba7{}{}", hex::encode(withdrawal_txid.as_byte_array()), hex::encode(withdrawal_index.to_be_bytes())),
            "value": format!("0x{}", hex::encode(withdrawal_amount.to_be_bytes())),
            "gas": gas * 2,
            "gasPrice": format!("0x{}", hex::encode(gas_price.to_be_bytes())),
            "chainId": 5655, // TODO: Accept as parameter
            "nonce": nonce
        }),
        "latest"
    ];
    let response: String = client.request("eth_call", params).await?;

    tracing::info!("withdraw response: {:?}", response);

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
    let response: String = client.request("eth_call", params).await.unwrap();

    let txid_str_slice = &response[2..66];
    let txid = hex::decode(txid_str_slice)
        .map_err(|e| BridgeError::Error(e.to_string()))
        .unwrap();
    // txid.reverse(); // TODO: we should need to reverse this, test this with declareWithdrawalFiller

    Ok(Txid::from_slice(&txid)?)
}
