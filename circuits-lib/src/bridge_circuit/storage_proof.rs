use alloy_primitives::Bytes;
use alloy_primitives::{Keccak256, U256};
use alloy_rpc_types::EIP1186StorageProof;
use jmt::{proof::SparseMerkleProof, KeyHash};

use super::structs::StorageProof;

const ADDRESS: [u8; 20] = hex_literal::hex!("3100000000000000000000000000000000000002");

// STORAGRE SLOTES of DATA STRUCTURES ON BRIDGE CONTRACT
const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000026");

const DEPOSIT_MAPPING_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000027");

/// Verifies Ethereum storage proofs related to deposit and withdrawal UTXOs.
///
/// # Parameters
///
/// - `storage_proof`: A reference to `StorageProof`, containing UTXO and deposit proofs.
/// - `state_root`: A 32-byte array representing the Ethereum state root.
///
/// # Returns
///
/// - A `String` representing the verified UTXO value.
///
/// # Panics
///
/// - If JSON deserialization fails.
/// - If the computed deposit storage key does not match the proof.
/// - If the computed UTXO storage key or deposit index is invalid.
/// - If the proof verification via `storage_verify` fails.
pub fn verify_storage_proofs(storage_proof: &StorageProof, state_root: [u8; 32]) -> String {
    let utxo_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_utxo)
            .expect("Failed to deserialize UTXO storage proof");
    let deposit_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_deposit_idx)
            .expect("Failed to deserialize deposit storage proof");

    let storage_address: U256 = {
        let mut keccak = Keccak256::new();
        keccak.update(UTXOS_STORAGE_INDEX);
        let hash = keccak.finalize();
        U256::from_be_bytes(
            <[u8; 32]>::try_from(&hash[..]).expect("Hash slice has incorrect length"),
        )
    };

    let storage_key: alloy_primitives::Uint<256, 4> =
        storage_address + U256::from(storage_proof.index * 2);

    let concatenated = [storage_proof.txid_hex, DEPOSIT_MAPPING_STORAGE_INDEX].concat();

    let deposit_key = {
        let mut keccak = Keccak256::new();
        keccak.update(concatenated);
        let mut hash = keccak.finalize().0;
        hash.reverse(); // Adjust endianness
        hash
    };

    if deposit_key != deposit_storage_proof.key.as_b256().0 {
        panic!("Invalid deposit storage key.");
    }

    if storage_key.to_le_bytes() != utxo_storage_proof.key.as_b256().0
        || U256::from(storage_proof.index) != deposit_storage_proof.value
    {
        panic!("Invalid withdrawal UTXO storage key.");
    }

    storage_verify(&deposit_storage_proof, state_root);

    storage_verify(&utxo_storage_proof, state_root);

    utxo_storage_proof.value.to_string()
}

/// Verifies an Ethereum storage proof against an expected root hash.
///
/// # Parameters
///
/// - `storage_proof`: A reference to an `EIP1186StorageProof` containing the key, value, and Merkle proof.
/// - `expected_root_hash`: A 32-byte array representing the expected root hash of the storage Merkle tree.
///
/// # Panics
///
/// - If Borsh deserialization of `storage_proof.proof[0]` fails.
/// - If Merkle proof verification fails.
fn storage_verify(storage_proof: &EIP1186StorageProof, expected_root_hash: [u8; 32]) {
    let storage_key = [
        b"Evm/s/",
        ADDRESS.as_slice(),
        &[32],
        U256::from_le_slice(&storage_proof.key.as_b256().0)
            .to_be_bytes::<32>()
            .as_slice(),
    ]
    .concat();

    let key_hash = KeyHash::with::<sha2::Sha256>(&storage_key);

    let proved_value = if storage_proof.proof[1] == Bytes::from("y") {
        // Storage value exists and it's serialized form is:
        let bytes = [&[32], storage_proof.value.to_be_bytes::<32>().as_slice()].concat();
        Some(bytes)
    } else {
        // Storage value does not exist
        None
    };

    let storage_proof: SparseMerkleProof<sha2::Sha256> =
        borsh::from_slice(&storage_proof.proof[0]).expect("Failed to deserialize storage proof");

    storage_proof
        .verify(jmt::RootHash(expected_root_hash), key_hash, proved_value)
        .expect("Account storage proof must be valid");
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    const STORAGE_PROOF: &[u8] =
        include_bytes!("../../../bridge-circuit-host/bin-files/storage_proof.bin");

    #[test]
    fn test_verify_storage_proofs() {
        let storage_proof: StorageProof = borsh::from_slice(STORAGE_PROOF).unwrap();

        let state_root: [u8; 32] =
            hex::decode("ee3922198db909ff1e9ae81ce87933bb6afcc136fd1411088f725ada5efced78")
                .expect("Valid hex, cannot fail")
                .try_into()
                .expect("Valid length, cannot fail");

        let user_wd_outpoint_str = verify_storage_proofs(&storage_proof, state_root);

        let user_wd_outpoint_bytes = num_bigint::BigUint::from_str(&user_wd_outpoint_str)
            .unwrap()
            .to_bytes_be();

        let expected_user_wd_outpoint_bytes = [
            147, 207, 2, 221, 145, 156, 136, 149, 25, 238, 110, 211, 245, 51, 30, 237, 238, 245,
            129, 239, 223, 144, 127, 37, 107, 63, 161, 147, 23, 142, 87, 91,
        ];

        assert_eq!(
            user_wd_outpoint_bytes, expected_user_wd_outpoint_bytes,
            "Invalid UTXO value"
        );
    }

    #[test]
    #[should_panic]
    fn test_verify_storage_proofs_invalid_proof() {
        let mut storage_proof: StorageProof = borsh::from_slice(STORAGE_PROOF).unwrap();

        let state_root: [u8; 32] =
            hex::decode("ee3922198db909ff1e9ae81ce87933bb6afcc136fd1411088f725ada5efced78")
                .expect("Valid hex, cannot fail")
                .try_into()
                .expect("Valid length, cannot fail");

        storage_proof.storage_proof_utxo = "invalid_proof".to_string();

        verify_storage_proofs(&storage_proof, state_root);
    }

    #[test]
    #[should_panic]
    fn test_verify_storage_proofs_invalid_state_root() {
        let storage_proof: StorageProof = borsh::from_slice(STORAGE_PROOF).unwrap();

        let state_root: [u8; 32] =
            hex::decode("ee3922198db909ff1e9ae81ce87933bb6afcc136fd1411088f725ada5efced79")
                .expect("Valid hex, cannot fail")
                .try_into()
                .expect("Valid length, cannot fail");

        verify_storage_proofs(&storage_proof, state_root);
    }
}
