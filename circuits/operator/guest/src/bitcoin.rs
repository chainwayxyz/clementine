use circuit_helpers::{
    hashes::calculate_double_sha256,
    core_tx::CoreTransaction,
};
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
    let tx: CoreTransaction<2, 3, 221> = env::read();
    assert_eq!(tx.outputs[0].taproot_address, output_address);
    assert_eq!(tx.calculate_txid(), tx_id);
}

pub fn verify_txid_input(tx_id: [u8; 32], input_utxo: [u8; 32]) -> [u8; 32] {
    let tx: CoreTransaction<2, 3, 221> = env::read();
    assert_eq!(tx.inputs[0].prev_tx_hash, input_utxo);
    return tx.calculate_txid();
}
