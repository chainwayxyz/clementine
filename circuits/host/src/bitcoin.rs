use crate::utils::json_to_obj;
use serde::{Deserialize, Serialize};
use bridge_core::btc::calculate_double_sha256;
use bitcoin::{blockdata::transaction::Transaction, consensus::Decodable};

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HostTransaction {
    txid: String,
    hash: String,
    version: i32,
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
    script_sig: VinScriptSig,
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
    hex: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoutScriptPubKey {
    hex: String,
    address: String,
}

pub fn from_json_to_host_tx(file_path: &str) -> HostTransaction {
    let tx_json = json_to_obj::<HostTransaction>(file_path);
    return tx_json.into();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinMerkleTree {
    depth: u32,
    nodes: Vec<Vec<[u8; 32]>>,
}

impl BitcoinMerkleTree {
    pub fn new(depth: u32, transactions: Vec<[u8; 32]>) -> Self {
        assert!(depth > 0, "Depth must be greater than 0");
        assert!(depth <= 254, "Depth must be less than or equal to 254");
        assert!(u32::pow(2, (depth) as u32) >= transactions.len() as u32, "Too many transactions for this depth");
        let mut tree = BitcoinMerkleTree {
            depth: depth,
            nodes: vec![],
        };

        // Populate leaf nodes
        tree.nodes.push(vec![]);
        for tx in transactions.iter() {
            tree.nodes[0].push(*tx);
        }
        println!("tree.nodes[0] length: {:?}", tree.nodes[0].len());

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = transactions.len();
        let mut prev_level_index_offset = 0;
        let mut preimage: [u8; 64] = [0; 64];
        while prev_level_size > 1 {
            // println!("curr_level_offset: {}", curr_level_offset);
            // println!("prev_level_size: {}", prev_level_size);
            // println!("prev_level_index_offset: {}", prev_level_index_offset);
            tree.nodes.push(vec![]);
            for i in 0..(prev_level_size / 2) {
                preimage[..32].copy_from_slice(&tree.nodes[curr_level_offset - 1 as usize][prev_level_index_offset + i * 2]);
                preimage[32..].copy_from_slice(&tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2 + 1]);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(&tree.nodes[curr_level_offset - 1][prev_level_index_offset + prev_level_size - 1]);
                preimage[32..].copy_from_slice(&tree.nodes[curr_level_offset - 1][prev_level_index_offset + prev_level_size - 1]);
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            curr_level_offset += 1;
            prev_level_size = (prev_level_size + 1) / 2;
            prev_level_index_offset = 0;
        }
        tree
    }

    // Returns the Merkle root
    pub fn root(&self) -> [u8; 32] {
        return self.nodes[self.nodes.len() - 1][0];
    }

    pub fn get_element(&self, level: u32, index: u32) -> [u8; 32] {
        return self.nodes[level as usize][index as usize];
    }

    pub fn get_idx_path(&self, index: u32) -> Vec<[u8; 32]> {
        assert!(index <= self.nodes[0].len() as u32 - 1, "Index out of bounds");
        let mut path = vec![];
        let mut level = 0;
        let mut i = index;
        while level < self.nodes.len() as u32 - 1 {
            if i % 2 == 1 {
                path.push(self.nodes[level as usize][i as usize - 1]);
            } else {
                if (self.nodes[level as usize].len() - 1) as u32 == i {
                    path.push(self.nodes[level as usize][i as usize]);
                } else {
                    path.push(self.nodes[level as usize][(i + 1) as usize]);
                }
            }
            level += 1;
            i = i / 2;
        }
        return path;
    }

    pub fn verify_tx_merkle_proof(&self, idx: u32) {
        let tx_id = self.nodes[0][idx as usize];
        let merkle_proof = self.get_idx_path(idx);
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = tx_id.clone();
        let mut index = idx;
        let mut level: u32 = 0;
        while level < self.depth {
            if index % 2 == 0 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize]);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                preimage[..32].copy_from_slice(&merkle_proof[level as usize]);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
            index = index / 2;
        }
        assert_eq!(combined_hash, self.root());
    }

    // pub fn calculate_root_with_merkle_proof(&self, tx_id: [u8; 32], merkle_proof: Vec<Node>) -> [u8; 32] {
    //     let mut preimage: [u8; 64] = [0; 64];
    //     let mut combined_hash: [u8; 32] = tx_id.clone();
    //     let mut level: u8 = 0;
    //     while level < self.depth {
    //         if merkle_proof[level as usize].index % 2 == 1 {
    //             preimage[..32].copy_from_slice(&combined_hash);
    //             preimage[32..].copy_from_slice(&merkle_proof[level as usize].data);
    //             combined_hash = calculate_double_sha256(&preimage);
    //         } else {
    //             preimage[..32].copy_from_slice(&merkle_proof[level as usize].data);
    //             preimage[32..].copy_from_slice(&combined_hash);
    //             combined_hash = calculate_double_sha256(&preimage);
    //         }
    //         level += 1;
    //     }
    //     combined_hash.reverse();
    //     return combined_hash;
    // }

}

pub fn parse_hex_to_btc_tx(
    tx_hex: &str,
) -> Result<Transaction, bitcoin::consensus::encode::Error> {
    if let Ok(reader) = hex::decode(tx_hex) {
        Transaction::consensus_decode(&mut &reader[..])
    } else {
        Err(bitcoin::consensus::encode::Error::ParseFailed(
            "Could not decode hex",
        ))
    }
}

pub fn from_btc_tx_to_host_tx(input: Transaction) -> HostTransaction {
    let txid = input.txid().to_string();
    let hash = input.wtxid().to_string();
    let version = input.version.0;
    let locktime = input.lock_time.to_consensus_u32();
    let mut vin: Vec<HostTxInput> = vec![];
    for input in input.input.iter() {
        let txid = input.previous_output.txid.to_string();
        let vout = input.previous_output.vout;
        let script_sig = VinScriptSig {
            hex: input.script_sig.to_hex_string()
        };
        let sequence = input.sequence.0;
        let host_tx_input = HostTxInput {
            txid,
            vout,
            script_sig,
            sequence,
        };
        vin.push(host_tx_input);
    }
    let mut vout: Vec<HostTxOutput> = vec![];
    for output in input.output.iter() {
        let value = output.value.to_btc();
        let n = output.script_pubkey.len() as u32;
        let script_pubkey = VoutScriptPubKey {
            hex: output.script_pubkey.to_hex_string(),
            address: output.script_pubkey.to_hex_string()
        };
        let host_tx_output = HostTxOutput {
            value,
            n,
            scriptPubKey: script_pubkey,
        };
        vout.push(host_tx_output);
    }
    let tx_id = input.txid();
    println!("{:?}", tx_id);
    let btc_tx_bytes = bitcoin::consensus::encode::serialize(&input);
    println!("{:?}", hex::encode(&btc_tx_bytes));
    let hex = hex::encode(&btc_tx_bytes);
    HostTransaction {
        txid,
        hash,
        version,
        locktime,
        vin,
        vout,
        hex,
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
        println!("{:?}", tx_vec);
        let merkle_tree = BitcoinMerkleTree::new(12, tx_vec.clone());
        for i in 0..tx_vec.len() {
            merkle_tree.verify_tx_merkle_proof(i as u32);
        }
    }

    #[test]
    fn test_parse_hex_to_btc_tx() {
        let hex: Value = json_to_obj("data/example_tx.json");
        println!("{:?}", hex);
        let btc_tx = parse_hex_to_btc_tx(hex["hex"].as_str().unwrap()).unwrap();
        println!("{:?}", btc_tx);
        println!("{:?}", btc_tx.txid());
    }

    #[test]
    fn test_from_btc_tx_to_host_tx() {
        let hex: Value = json_to_obj("data/example_tx.json");
        let try_btc_tx = parse_hex_to_btc_tx(hex["hex"].as_str().unwrap()).unwrap();
        let host_tx = from_btc_tx_to_host_tx(try_btc_tx);
        println!("{:?}", host_tx);
    }

    

}