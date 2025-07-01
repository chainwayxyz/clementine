use crate::bitvm_client::SECP;
use crate::citrea::{CitreaClient, CitreaClientT, LIGHT_CLIENT_ADDRESS, SATS_TO_WEI_MULTIPLIER};
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::WithdrawParams;
use crate::test::common::citrea::parameters::get_citrea_deposit_params;
use crate::test::common::citrea::{self, get_citrea_safe_withdraw_params, SECRET_KEYS};
use crate::test::common::generate_withdrawal_transaction_and_signature;
use crate::EVMAddress;
use alloy::primitives::U256;
use alloy::sol_types::SolValue;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{schnorr, SecretKey};
use bitcoin::{Address, Amount, Block, OutPoint, Transaction, TxOut};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig, SequencerConfig};
use citrea_e2e::node::Node;
use eyre::Context;
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

    let response: String = client
        .request("eth_call", params)
        .await
        .wrap_err("Failed to get block number")?;

    let decoded_hex = hex::decode(&response[2..]).map_err(|e| eyre::eyre!(e.to_string()))?;
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

    let response: String = client
        .request("eth_getBalance", params)
        .await
        .wrap_err("Failed to get balance")?;
    let ret = u128::from_str_radix(&response[2..], 16)
        .map_err(|e| eyre::eyre!("Can't convert hex to int: {}", e))?;

    Ok(ret)
}

/// Deposits a transaction to Citrea. This function is different from `contract.deposit` because it
/// won't directly talk with EVM but with Citrea. So that authorization can be done (Citrea will
/// block this call if it isn't an operator).
pub async fn deposit(
    rpc: &ExtendedRpc,
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let params = get_citrea_deposit_params(rpc, transaction, block, block_height, txid).await?;

    let _response: () = client
        .request(
            "citrea_sendRawDepositTransaction",
            rpc_params!(hex::encode(params.abi_encode_params())),
        )
        .await
        .wrap_err("Failed to send deposit transaction")?;

    Ok(())
}
