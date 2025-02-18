//! # Citrea Request Builder

use crate::errors::BridgeError;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

/// https://gist.github.com/okkothejawa/a9379b02a16dada07a2b85cbbd3c1e80
///
/// TODO: withdrawal_index is u256, convert it to [u8; 32]
pub async fn withdrawal_utxos(
    client: HttpClient,
    withdrawal_index: u32,
) -> Result<Txid, BridgeError> {
    let params = rpc_params![
        json!({
            "to": "0x3100000000000000000000000000000000000002",
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
