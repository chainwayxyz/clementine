use bridge_core::{btc::calculate_double_sha256, utils::{from_hex_to_tx, from_bytes_to_hex, char_array_to_str}};
use risc0_zkvm::guest::env;


pub fn verify_txid_merkle_path(txid: [u8; 32], merkle_root: [u8; 32]) {
    let mut hash = txid;
    let levels = env::read();
    for _ in 0..levels {
        let node: [u8; 32] = env::read();
        let mut preimage: [u8; 64] = [0; 64];
        preimage[..32].copy_from_slice(&hash);
        preimage[32..].copy_from_slice(&node);
        hash = calculate_double_sha256(&preimage);
    }
    assert_eq!(hash, merkle_root);
}

pub fn verify_txid_output_address(tx_id: [u8; 32], output_address: [u8; 32]) {
    let size_in_bytes = env::read();
    let mut tx_bytes: [u8; 1024] = [0; 1024];
    for i in 0..1024 {
        tx_bytes[i] = env::read();
    }
    let (tx_hex, size_in_hex) = from_bytes_to_hex(tx_bytes, size_in_bytes);
    let mut hex_buffer = [0u8; 2048];
    let tx_hex_str = char_array_to_str(&mut hex_buffer, &tx_hex, size_in_hex).unwrap();
    let tx = from_hex_to_tx(&tx_hex_str);
    let calculated_tx_id = tx.calculate_txid();
    assert_eq!(calculated_tx_id, tx_id);
    let calculated_output_address = tx.outputs[0].script_pub_key;
    assert_eq!(calculated_output_address, output_address[..32]);
}

pub fn verify_txid_input(tx_id: [u8; 32], input_utxo: [u8; 32]) -> [u8; 32] {
    let size_in_bytes = env::read();
    let mut tx_bytes: [u8; 1024] = [0; 1024];
    for i in 0..1024 {
        tx_bytes[i] = env::read();
    }
    let (tx_hex, size_in_hex) = from_bytes_to_hex(tx_bytes, size_in_bytes);
    let mut hex_buffer = [0u8; 2048];
    let tx_hex_str = char_array_to_str(&mut hex_buffer, &tx_hex, size_in_hex).unwrap();
    let tx = from_hex_to_tx(&tx_hex_str);
    let calculated_tx_id = tx.calculate_txid();
    assert_eq!(calculated_tx_id, tx_id);
    let calculated_input_utxo = tx.inputs[0].prev_tx_hash;
    assert_eq!(calculated_input_utxo, input_utxo);
    return [0; 32];
}


