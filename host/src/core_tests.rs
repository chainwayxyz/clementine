#[cfg(test)]
mod tests {
    use bridge_core::{utils::from_hex_to_bytes, merkle::MerkleTree};
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
                let (tx_id_arr, size) = from_hex_to_bytes(tx_id_str);
                let tx_id_arr_first_32_bytes = tx_id_arr[0..32].try_into().unwrap();
                tx_id_arr_first_32_bytes
            })
            .collect::<Vec<[u8; 32]>>();
        let merkle_tree = MerkleTree::new(12, &transactions[0..3730], 3730);

        let mut merkle_root = merkle_tree.merkle_root();
        // println!("merkle_root: {:?}", merkle_root);
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
}
