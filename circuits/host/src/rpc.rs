use dotenv::dotenv;
use std::{env, collections::HashMap, vec, fs::File, io::Write};
// use bitcoincore_rpc::{Auth, Client, RpcApi};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION};
use serde_json::{json, Value};

use crate::bitcoin::BitcoinMerkleTree;

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

    let blockhash_hex = hex::encode(cur_blockhash);

    let body = json!({
        "jsonrpc": "1.0",
        "id": "rustclient",
        "method": "getblock",
        "params": [blockhash_hex, 1]
    });

    let res = client.post(rpc_url)
        .headers(headers)
        .json(&body)
        .send()
        .await.unwrap();

    let response_json: Value = res.json().await.unwrap();

    // let json_string = serde_json::to_string(&response_json).unwrap();
    // println!("json_string: {:?}", json_string);

    // let mut file = File::create("./data/block_verbose_2.json").unwrap();
    // file.write_all(json_string.as_bytes()).unwrap();

    let tx_id_array = response_json["result"]["tx"].as_array().unwrap();

    let mut tx_id_map: HashMap<String, usize> = HashMap::new();
    for (index, tx_id) in tx_id_array.iter().enumerate() {
        if let Some(txid_str) = tx_id.as_str() {
            tx_id_map.insert(txid_str.to_string(), index);
        }
    }
    // println!("tx_id_map: {:?}", tx_id_map);

    let mut withdrawal_indices = HashMap::new();
    for withdrawal_tx_id in all_withdrawals {
        let withdrawal_tx_id_hex = hex::encode(withdrawal_tx_id);
        if let Some(&index) = tx_id_map.get(&withdrawal_tx_id_hex) {
            withdrawal_indices.insert(withdrawal_tx_id, index);
        }
    }
    // println!("withdrawal_indices: {:?}", withdrawal_indices);

    let tx_id_bytes_vec = tx_id_array.iter().map(|tx_id| {
        if let Some(txid_str) = tx_id.as_str() {
            let mut bytes: Vec<u8> = hex::decode(txid_str).unwrap().try_into().unwrap();
            bytes.reverse();
            bytes.try_into().unwrap()
        } else {
            let empty = [0u8; 32];
            empty
        }
    }).collect::<Vec<[u8; 32]>>();

    let depth = (tx_id_array.len() - 1).ilog(2) + 1;
    let merkle_tree = BitcoinMerkleTree::new(depth, tx_id_bytes_vec);
    // println!("merkle_tree: {:?}", merkle_tree);
    let mut root_bytes = merkle_tree.root();
    // println!("root_bytes: {:?}", root_bytes);
    root_bytes.reverse();
    // println!("root_bytes: {:?}", root_bytes);
    let root = hex::encode(root_bytes);
    let rpc_root = response_json["result"]["merkleroot"].as_str().unwrap();
    // println!("rpc root: {:?}", rpc_root);
    assert_eq!(root, rpc_root);
    // println!("withdrawal map: {:?}", withdrawal_indices);

    let mut merkle_path_vec = Vec::new();
    for (_, index) in withdrawal_indices {
        let merkle_path = merkle_tree.get_idx_path(index as u32);
        // println!("merkle_path: {:?}", merkle_path);
        merkle_tree.verify_tx_merkle_proof(index as u32);
        merkle_path_vec.push(merkle_path);
    }

    return merkle_path_vec;

}

#[cfg(test)]
mod tests {

    use crate::core_tx_utils::from_hex64_to_bytes32;

    use super::*;

    #[test]
    fn test_handle_withdrawals() {
        let cur_blockhash_hex = "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b";
        let cur_blockhash = from_hex64_to_bytes32(cur_blockhash_hex);
        let mut all_withdrawals = Vec::new();
        let withdraw_1: [u8; 32] = hex::decode("4206f171f06913b1d40597edcaf75780559231fb504c49ba85a4a9ae949e8b95").unwrap().try_into().unwrap();
        let withdraw_2: [u8; 32] = hex::decode("13e3167d46334600b59a5aa286dd02147ac33e64bfc2e188e1f0c0a442182584").unwrap().try_into().unwrap();
        all_withdrawals.push(withdraw_1);
        all_withdrawals.push(withdraw_2);
        // println!("all_withdrawals: {:?}", all_withdrawals);
        let merkle_paths = handle_withdrawals(all_withdrawals, cur_blockhash);
        println!("merkle_paths: {:?}", merkle_paths);
    }
}