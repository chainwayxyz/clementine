use std::collections::HashMap;

use bitcoin::{hashes::Hash, Address, BlockHash, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use crate::bitcoin_merkle::BitcoinMerkleTree;

pub fn handle_withdrawals(
    rpc: &Client,
    all_withdrawals: Vec<Txid>,
    cur_blockhash: [u8; 32],
) -> Vec<Vec<[u8; 32]>> {
    let block = rpc
        .get_block(&BlockHash::from_byte_array(cur_blockhash))
        .unwrap();

    // let json_string = serde_json::to_string(&response_json).unwrap();
    // println!("json_string: {:?}", json_string);

    // let mut file = File::create("./data/block_verbose_2.json").unwrap();
    // file.write_all(json_string.as_bytes()).unwrap();

    let tx_id_array = block
        .txdata
        .iter()
        .map(|tx| tx.txid())
        .collect::<Vec<Txid>>();

    let mut tx_id_map: HashMap<Txid, usize> = HashMap::new();
    for (index, tx_id) in tx_id_array.iter().enumerate() {
        tx_id_map.insert(*tx_id, index);
    }
    // println!("tx_id_map: {:?}", tx_id_map);

    let mut withdrawal_indices = HashMap::new();
    for withdrawal_tx_id in all_withdrawals {
        if let Some(&index) = tx_id_map.get(&withdrawal_tx_id) {
            withdrawal_indices.insert(withdrawal_tx_id, index);
        }
    }
    // println!("withdrawal_indices: {:?}", withdrawal_indices);

    let tx_id_bytes_vec = tx_id_array
        .iter()
        .map(|tx_id| {
            let bytes = tx_id.to_byte_array();
            // bytes.reverse();
            bytes.try_into().unwrap()
        })
        .collect::<Vec<[u8; 32]>>();

    let merkle_tree = BitcoinMerkleTree::new(tx_id_bytes_vec);
    // println!("merkle_tree: {:?}", merkle_tree);
    let mut root_bytes = merkle_tree.root();
    // println!("root_bytes: {:?}", root_bytes);
    root_bytes.reverse();
    // println!("root_bytes: {:?}", root_bytes);
    let root = hex::encode(root_bytes);
    let rpc_root = block.compute_merkle_root().unwrap().to_string();
    // println!("rpc root: {:?}", rpc_root);
    assert_eq!(root, rpc_root);
    // println!("withdrawal map: {:?}", withdrawal_indices);

    let mut merkle_path_vec = Vec::new();
    for (_, index) in withdrawal_indices {
        let merkle_path = merkle_tree.get_idx_path(index as u32);
        // println!("merkle_path: {:?}", merkle_path);
        // merkle_tree.verify_tx_merkle_proof(index as u32);
        merkle_path_vec.push(merkle_path);
    }

    return merkle_path_vec;
}

pub fn pay_withdrawals(rpc: &Client, withdrawal_addresses: Vec<Address>) -> BlockHash {
    withdrawal_addresses.iter().for_each(|address| {
        rpc.send_to_address(
            &address,
            bitcoin::Amount::from_sat(100_000_000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    });
    let address = rpc.get_new_address(None, None).unwrap().assume_checked();

    rpc.generate_to_address(1, &address).unwrap()[0]
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::{rngs::OsRng, seq::SliceRandom};
    use crate::extended_rpc::ExtendedRpc;

    use super::*;

    #[test]
    fn test_handle_withdrawals() {
        let num_withdrawals = 5;
        let rpc = ExtendedRpc::new();

        // TODO: Make 2 dummy transactions and add them to the blockchain

        let block_hash = rpc.generate_dummy_block()[0];
        let transactions = rpc.inner.get_block(&block_hash).unwrap().txdata;
        //  randomly sample 5 transactions
        let mut rng = OsRng;
        let all_withdrawals = transactions
            .choose_multiple(&mut rng, num_withdrawals)
            .into_iter()
            .map(|tx| tx.txid())
            .collect::<Vec<Txid>>();

        let merkle_paths =
            handle_withdrawals(&rpc.inner, all_withdrawals, block_hash.to_byte_array());
        assert_eq!(merkle_paths.len(), num_withdrawals);
    }

    #[test]
    fn test_pay_withdrawals() {
        let rpc = ExtendedRpc::new();
        let mut withdrawal_addresses = Vec::new();
        for _ in 0..5 {
            withdrawal_addresses.push(rpc.inner.get_new_address(None, None).unwrap().assume_checked());
        }

        let block_hash = pay_withdrawals(&rpc.inner, withdrawal_addresses);
        let _block = rpc.inner.get_block(&block_hash).unwrap();
        // TODO: check that the block contains the withdrawal transactions
    }
}
