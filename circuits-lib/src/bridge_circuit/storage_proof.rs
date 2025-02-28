use crate::bridge_circuit_core::structs::StorageProof;
use alloy_primitives::Bytes;
use alloy_primitives::{Keccak256, U256};
use alloy_rpc_types::EIP1186StorageProof;
use jmt::{proof::SparseMerkleProof, KeyHash};

const ADDRESS: [u8; 20] = hex_literal::hex!("3100000000000000000000000000000000000002");

// STORAGRE SLOTES of DATA STRUCTURES ON BRIDGE CONTRACT
const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000026");
const DEPOSIT_MAPPING_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000027");

pub fn verify_storage_proofs(storage_proof: &StorageProof, state_root: [u8; 32]) -> String {
    let utxo_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_utxo).unwrap();
    let deposit_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_deposit_idx).unwrap();

    println!(
        "deposit storage proof value {:?}",
        deposit_storage_proof.value
    );

    let mut keccak = Keccak256::new();
    keccak.update(UTXOS_STORAGE_INDEX);
    let hash = keccak.finalize();

    let storage_address: U256 =
        U256::from_be_bytes(<[u8; 32]>::try_from(&hash[..]).expect("Slice with incorrect length"));
    let storage_key: alloy_primitives::Uint<256, 4> =
        storage_address + U256::from(storage_proof.index * 2);

    let mut concantenated: [u8; 64] = [0; 64];
    concantenated[..32].copy_from_slice(&storage_proof.txid_hex);
    concantenated[32..].copy_from_slice(&DEPOSIT_MAPPING_STORAGE_INDEX);

    let mut keccak = Keccak256::new();
    keccak.update(&concantenated);
    let mut hash = keccak.finalize().0;
    hash.reverse(); // To match endianess

    if hash != deposit_storage_proof.key.as_b256().0 {
        panic!("Invalid deposit storage key.");
    }

    if storage_key.to_le_bytes() != utxo_storage_proof.key.as_b256().0
        || U256::from(storage_proof.index) != deposit_storage_proof.value
    {
        panic!("Invalid withdrawal UTXO storage key.");
    }

    storage_verify(&deposit_storage_proof, state_root);
    println!("Deposit storage proof verification successful!");

    storage_verify(&utxo_storage_proof, state_root);
    println!("UTXO storage proof verification successful!");

    utxo_storage_proof.value.to_string()
}

fn storage_verify(storage_proof: &EIP1186StorageProof, expected_root_hash: [u8; 32]) {
    println!("key {:?}", storage_proof.key.as_b256().0);
    let storage_key = [
        b"Evm/s/",
        ADDRESS.as_slice(),
        &[32],
        U256::from_le_slice(&storage_proof.key.as_b256().0)
            .to_be_bytes::<32>()
            .as_slice(),
    ]
    .concat();
    let key_hash = KeyHash::with::<sha2::Sha256>(storage_key.clone());

    let proved_value = if storage_proof.proof[1] == Bytes::from("y") {
        // Storage value exists and it's serialized form is:
        let bytes = [&[32], storage_proof.value.to_be_bytes::<32>().as_slice()].concat();
        Some(bytes)
    } else {
        // Storage value does not exist
        None
    };

    let storage_proof: SparseMerkleProof<sha2::Sha256> =
        borsh::from_slice(&storage_proof.proof[0]).unwrap();

    storage_proof
        .verify(jmt::RootHash(expected_root_hash), key_hash, proved_value)
        .expect("Account storage proof must be valid");
}
