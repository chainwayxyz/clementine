use crate::utils::json_to_obj;
use serde::{Deserialize, Serialize};
use bridge_core::btc::calculate_double_sha256;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostTransaction {
    txid: String,
    hash: String,
    version: i32,
    size: u32,
    vsize: u32,
    weight: u32,
    locktime: u32,
    vin: Vec<HostTxInput>,
    vout: Vec<HostTxOutput>,
    hex: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostTxInput {
    txid: String,
    vout: u32,
    scriptSig: VinScriptSig,
    txinwitness: Vec<String>,
    sequence: u32,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostTxOutput {
    value: f64,
    n: u32,
    scriptPubKey: VoutScriptPubKey,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VinScriptSig {
    asm: String,
    hex: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoutScriptPubKey {
    asm: String,
    desc: String,
    hex: String,
    address: String,
}

pub fn from_json_to_host_tx(file_path: &str) -> HostTransaction {
    let tx_json = json_to_obj::<HostTransaction>(file_path);
    return tx_json.into();
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Node {
    data: [u8; 32], // Placeholder for the hash
    level: u8,
    index: u32,
}

impl Node {
    fn new(data: [u8; 32], level: u8, index: u32) -> Self {
        Node { data, level: level, index: index}
    }

    pub fn get_data(&self) -> [u8; 32] {
        return self.data;
    }

    pub fn get_index(&self) -> u32 {
        return self.index;
    }
    pub fn get_level(&self) -> u8 {
        return self.level;
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinMerkleTree {
    depth: u8,
    nodes: Vec<Node>,
    number_of_transactions: u32,
    number_of_elems_per_level: Vec<u32>,
}

impl BitcoinMerkleTree {
    pub fn new(depth: u8, transactions: Vec<[u8; 32]>, number_of_txs: u32) -> Self {
        assert!(depth > 0, "Depth must be greater than 0");
        assert!(depth <= 254, "Depth must be less than or equal to 254");
        assert!(u32::pow(2, (depth) as u32) >= number_of_txs, "Too many transactions for this depth");
        assert!(number_of_txs == transactions.len() as u32, "Number of transactions does not match the length of the transactions array");
        let mut tree = BitcoinMerkleTree {
            depth: depth,
            nodes: vec![],
            number_of_transactions: number_of_txs,
            number_of_elems_per_level: vec![],
        };

        // Populate leaf nodes
        for (i, tx) in transactions.iter().enumerate() {
            let tx_clone = tx.clone();
            tree.nodes.push(Node::new(tx_clone, 0, i as u32));
        }
        tree.number_of_elems_per_level.push(number_of_txs);

        // Construct the tree
        let mut curr_level_offset: u8 = 1;
        let mut prev_level_size = transactions.len();
        let mut prev_level_index_offset = 0;
        let mut curr_level_index_offset = transactions.len();

        while prev_level_size > 1 {
            for i in 0..(prev_level_size / 2) {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(&tree.nodes[prev_level_index_offset + i * 2].data);
                preimage[32..].copy_from_slice(&tree.nodes[prev_level_index_offset + i * 2 + 1].data);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes.push(Node::new(combined_hash, curr_level_offset as u8, i as u32));
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(&tree.nodes[prev_level_index_offset + prev_level_size - 1].data);
                preimage[32..].copy_from_slice(&tree.nodes[prev_level_index_offset + prev_level_size - 1].data);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes.push(Node::new(combined_hash, curr_level_offset as u8, (prev_level_size / 2) as u32));
            }
            curr_level_offset += 1;
            prev_level_size = (prev_level_size + 1) / 2;
            prev_level_index_offset = curr_level_index_offset;
            curr_level_index_offset += prev_level_size;
            tree.number_of_elems_per_level.push(prev_level_size as u32);
        }
        tree
    }

    // Returns the Merkle root
    pub fn root(&self) -> [u8; 32] {
        return self.nodes.last().unwrap().data;
    }

    pub fn get_root_index(&self) -> u32 {
        return self.nodes.last().unwrap().index;
    }

    pub fn get_element(&self, level: u8, index: u32) -> Node {
        let mut no_of_tx = self.number_of_transactions;
        let mut idx = 0;
        let mut i = 0;
        while i < level {
            idx += no_of_tx;
            no_of_tx = (no_of_tx + 1) / 2;
            i += 1;
        }
        return self.nodes[(idx + index) as usize];
    }

    pub fn get_element_from_index(&self, index: u32) -> Node {
        return self.nodes[index as usize];
    }

    pub fn get_no_of_elem_arr(&self) -> Vec<u32> {
        return self.number_of_elems_per_level.clone();
    }

    pub fn get_tx_id_path(&self, index: u32) -> Vec<Node> {
        assert!(index < self.number_of_transactions, "Index out of bounds");
        let mut path: Vec<Node> = vec![];
        let mut i = index;
        let mut level: u8 = 0;
        while level < self.depth {
            if i % 2 == 1 {
                path[level as usize] = self.get_element(level, i - 1);
            } else {
                if (self.number_of_elems_per_level[level as usize] - 1) == i {
                    path[level as usize] = self.get_element(level, i);
                } else {
                    path[level as usize] = self.get_element(level, i + 1);
                }
            }
            level += 1;
            i = i / 2;
        }
        return path;
    }

    pub fn calculate_root_with_merkle_proof(&self, tx_id: [u8; 32], merkle_proof: Vec<Node>) -> [u8; 32] {
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = tx_id.clone();
        let mut level: u8 = 0;
        while level < self.depth {
            if merkle_proof[level as usize].index % 2 == 1 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize].data);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                preimage[..32].copy_from_slice(&merkle_proof[level as usize].data);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
        }
        combined_hash.reverse();
        return combined_hash;
    }

}

#[cfg(test)]
mod tests {
    use serde_json::Value;


    use super::*;

    #[test]
    fn test_from_json_to_host_tx() {
        let tx = from_json_to_host_tx("data/example_tx.json");
        println!("{:?}", tx);
    }

    #[test]
    fn test_merkle_tree() {
        let block_json: Value = json_to_obj("data/getblock.json");
        let tx_vec: Vec<[u8; 32]> = block_json.clone()["result"]["tx"].as_array().unwrap().iter().map(|tx| {
            let tx_id = tx.as_str().unwrap();
            let mut tx_id_bytes = hex::decode(tx_id).unwrap();
            tx_id_bytes.reverse();
            tx_id_bytes.try_into().unwrap()
        }).collect();
        let merkle_tree = BitcoinMerkleTree::new(12, tx_vec.clone(), tx_vec.len() as u32);
        println!("{:?}", hex::encode(merkle_tree.root()));
    }
}