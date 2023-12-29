use dotenv::dotenv;
use std::env;
// use bitcoincore_rpc::{Auth, Client, RpcApi};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION};
use serde_json::json;

//For each block, return the merkle path of each withdrawal transaction

#[tokio::main]
async fn handle_withdrawals(all_withdrawals: Vec<[u8; 32]>, cur_blockhash: [u8; 32]) -> Vec<Vec<[u8; 32]>> {
    dotenv().ok();
    let rpc_url = env::var("RPC_URL").unwrap();
    let rpc_bearer_token = env::var("RPC_BEARER_TOKEN").unwrap();
    // let rpc_cookie = env::var("RPC_COOKIE").unwrap();

    // let rpc_username = env::var("RPC_USERNAME").unwrap();
    // let rpc_password = env::var("RPC_PASSWORD").unwrap();
    // let rpc = Client::new(
    //     &rpc_url,
    //     Auth::UserPass(rpc_username, rpc_password),
    // ).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", rpc_bearer_token)).unwrap());

    let client = reqwest::Client::new();

    let body = json!({
        "jsonrpc": "1.0",
        "id": "rustclient",
        "method": "getrawtransaction",
        "params": [
            "9bac53ea183fd9b7044997a3db3dea3ecf5552256bb1575912fa2556f9973e54",
            true
        ]
    });

    let res = client.post("https://svc.blockdaemon.com/bitcoin/mainnet/native")
        .headers(headers)
        .json(&body)
        .send()
        .await.unwrap();

    let response_text = res.text().await.unwrap();

    println!("Response: {}", response_text);

    return Vec::new();

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_withdrawals() {
        let all_withdrawals = Vec::new();
        let cur_blockhash = [0; 32];
        let merkle_paths = handle_withdrawals(all_withdrawals, cur_blockhash);
        assert_eq!(merkle_paths.len(), 0);
    }
}