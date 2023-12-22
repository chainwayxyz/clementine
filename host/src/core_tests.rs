#[cfg(test)]
mod tests {

    use bridge_core::{
        merkle::MerkleTree,
        pool::{BufferPool, TxInputPool, TxOutputPool},
        tx::{Transaction, TxInput, TxOutput},
        utils::{from_hex_to_bytes, from_hex_to_tx},
    };
    use serde_json::Value;

    use crate::utils::json_to_obj;

    #[test]
    fn test_merkle_tree() {
        let tx_info_from_json = json_to_obj::<Value>("../host/data/getblock.json");
        let tx_id_arr = tx_info_from_json["result"]["tx"].as_array().unwrap();

        let transactions = tx_id_arr
            .iter()
            .map(|tx_id| {
                let tx_id_str = tx_id.as_str().unwrap();
                let (tx_id_arr, _) = from_hex_to_bytes(tx_id_str);
                let tx_id_arr_first_32_bytes = tx_id_arr[0..32].try_into().unwrap();
                tx_id_arr_first_32_bytes
            })
            .collect::<Vec<[u8; 32]>>();
        let merkle_tree = MerkleTree::new(12, &transactions[0..3730], 3730);

        let mut merkle_root = merkle_tree.merkle_root();
        merkle_root.reverse();
        let hex_merkle_root = hex::encode(merkle_root);
        println!("hex_merkle_root: {:?}", hex_merkle_root);

        let no_of_elem_arr = merkle_tree.get_no_of_elem_arr();
        println!("no_of_elem_arr: {:?}", no_of_elem_arr);

        let tx_id_path0 = merkle_tree.get_tx_id_path(31);
        let hex_tx_id_path_idx0 = tx_id_path0
            .iter()
            .map(|node| {
                let tx_id_clone = node.get_index().clone();
                tx_id_clone.to_string()
            })
            .collect::<Vec<String>>();
        println!("hex_tx_id_path_idx: {:?}", hex_tx_id_path_idx0);

        let tx_id_path1 = merkle_tree.get_tx_id_path(3729);
        let hex_tx_id_path1 = tx_id_path1
            .iter()
            .map(|node| {
                let tx_id_clone = node.get_index().clone();
                tx_id_clone.to_string()
            })
            .collect::<Vec<String>>();
        println!("hex_tx_id_path: {:?}", hex_tx_id_path1);

        let tx_id_path2 = merkle_tree.get_tx_id_path(1648);
        let hex_tx_id_path2 = tx_id_path2
            .iter()
            .map(|node| {
                let tx_id_clone = node.get_index().clone();
                tx_id_clone.to_string()
            })
            .collect::<Vec<String>>();
        println!("hex_tx_id_path: {:?}", hex_tx_id_path2);

        let tx_id_path3 = merkle_tree.get_tx_id_path(769);
        let hex_tx_id_path3 = tx_id_path3
            .iter()
            .map(|node| {
                let tx_id_clone = node.get_index().clone();
                tx_id_clone.to_string()
            })
            .collect::<Vec<String>>();
        println!("hex_tx_id_path: {:?}", hex_tx_id_path3);

        let tx_id_path4 = merkle_tree.get_tx_id_path(0);
        let hex_tx_id_path4 = tx_id_path4
            .iter()
            .map(|node| {
                let tx_id_clone = node.get_index().clone();
                tx_id_clone.to_string()
            })
            .collect::<Vec<String>>();
        println!("hex_tx_id_path: {:?}", hex_tx_id_path4);

        let test_calculate_root0 = merkle_tree.calculate_root_with_merkle_proof(
            merkle_tree.get_element(0, 31).get_data(),
            tx_id_path0,
        );
        let test_calculate_root_str0 = hex::encode(test_calculate_root0);
        println!("test_calculate_root: {:?}", test_calculate_root_str0);

        let test_calculate_root1 = merkle_tree.calculate_root_with_merkle_proof(
            merkle_tree.get_element(0, 3729).get_data(),
            tx_id_path1,
        );
        let test_calculate_root_str1 = hex::encode(test_calculate_root1);
        println!("test_calculate_root: {:?}", test_calculate_root_str1);

        let test_calculate_root2 = merkle_tree.calculate_root_with_merkle_proof(
            merkle_tree.get_element(0, 1648).get_data(),
            tx_id_path2,
        );
        let test_calculate_root_str2 = hex::encode(test_calculate_root2);
        println!("test_calculate_root: {:?}", test_calculate_root_str2);

        let test_calculate_root3 = merkle_tree.calculate_root_with_merkle_proof(
            merkle_tree.get_element(0, 769).get_data(),
            tx_id_path3,
        );
        let test_calculate_root_str3 = hex::encode(test_calculate_root3);
        println!("test_calculate_root: {:?}", test_calculate_root_str3);

        let test_calculate_root4 = merkle_tree.calculate_root_with_merkle_proof(
            merkle_tree.get_element(0, 0).get_data(),
            tx_id_path4,
        );
        let test_calculate_root_str4 = hex::encode(test_calculate_root4);
        println!("test_calculate_root: {:?}", test_calculate_root_str4);

        let root_index = merkle_tree.get_root_index();
        let root_element = merkle_tree.get_element_from_index(root_index);
        println!("root_element: {:?}", root_element);
    }

    #[test]
    fn test_buffer_pool() {
        let mut buffer_pool = BufferPool::new(10);
        buffer_pool[0] = 1;
        buffer_pool[1] = 2;
        buffer_pool[2] = 3;
        buffer_pool[3] = 4;
        buffer_pool[4] = 5;
        buffer_pool[5] = 6;
        buffer_pool[6] = 7;
        buffer_pool[7] = 8;
        buffer_pool[8] = 9;
        buffer_pool[9] = 10;
        println!("buffer_pool: {:?}", buffer_pool);
        let buffer_pool_clone = buffer_pool.clone();
        println!("buffer_pool_clone: {:?}", buffer_pool_clone);
        let buffer_pool_slice = &buffer_pool[0..5];
        println!("buffer_pool_slice: {:?}", buffer_pool_slice);
        let buffer_pool_slice_clone = buffer_pool_slice;
        println!("buffer_pool_slice_clone: {:?}", buffer_pool_slice_clone);
    }

    #[test]
    fn test_tx_input() {
        let tx_input = TxInput::new(
            [0u8; 32],
            0,
            0,
            BufferPool::Zero([0]),
            0,
        );
        println!("tx_input: {:?}", tx_input);
        let tx_input_clone = tx_input.clone();
        println!("tx_input_clone: {:?}", tx_input_clone);
        let tx_input_bytes = tx_input.as_bytes();
        println!("tx_input_bytes: {:?}", tx_input_bytes);
    }

    #[test]
    fn test_tx_output() {
        let tx_output = TxOutput {
            value: 0,
            script_pub_key_size: 0,
            script_pub_key: BufferPool::Zero([0]),
        };
        println!("tx_output: {:?}", tx_output);
        let tx_output_clone = tx_output.clone();
        println!("tx_output_clone: {:?}", tx_output_clone);
    }

    #[test]
    fn test_transaction() {
        let transaction = Transaction {
            version: 0,
            input_count: 0,
            inputs: TxInputPool::new(0),
            output_count: 0,
            outputs: TxOutputPool::new(0),
            lock_time: 0,
        };
        println!("transaction: {:?}", transaction);
        let transaction_clone = transaction.clone();
        println!("transaction_clone: {:?}", transaction_clone);
    }

    #[test]
    fn test_from_hex_to_bytes() {
        let input = "0100000001098ebbff18cf40ad3ba02ded7d3558d7ca6ee96c990c8fdfb99cf61d88ad2c680100000000ffffffff01f0a29a3b000000001976a914012e2ba6a051c033b03d712ca2ea00a35eac1e7988ac00000000";
        let (bytes, size) = from_hex_to_bytes(input);
        println!("bytes: {:?}", bytes);
        println!("size: {:?}", size);
    }

    #[test]
    fn test_hex_to_tx() {
        let input = "0100000001098ebbff18cf40ad3ba02ded7d3558d7ca6ee96c990c8fdfb99cf61d88ad2c680100000000ffffffff01f0a29a3b000000001976a914012e2ba6a051c033b03d712ca2ea00a35eac1e7988ac00000000";
        let tx = from_hex_to_tx(input);
        println!("tx: {:?}", tx);
    }

}
