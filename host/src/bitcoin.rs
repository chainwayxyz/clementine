use crate::utils::json_to_obj;

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_json_to_host_tx() {
        let tx = from_json_to_host_tx("data/example_tx.json");
        println!("{:?}", tx);
    }

}