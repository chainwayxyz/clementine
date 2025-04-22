use alloy_primitives::Bytes;
use alloy_primitives::{Keccak256, U256};
use alloy_rpc_types::EIP1186StorageProof;
use jmt::KeyHash;
use sha2::{Digest, Sha256};

use super::structs::StorageProof;

const ADDRESS: [u8; 20] = hex_literal::hex!("3100000000000000000000000000000000000002");

// STORAGRE SLOTES of DATA STRUCTURES ON BRIDGE CONTRACT
const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000007");

const DEPOSIT_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000008");

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
pub fn verify_storage_proofs(
    storage_proof: &StorageProof,
    state_root: [u8; 32],
) -> (String, [u8; 32]) {
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

    let storage_address_deposit: U256 = {
        let mut keccak = Keccak256::new();
        keccak.update(DEPOSIT_STORAGE_INDEX);
        let hash = keccak.finalize();
        U256::from_be_bytes(
            <[u8; 32]>::try_from(&hash[..]).expect("Hash slice has incorrect length"),
        )
    };

    let deposit_storage_key: alloy_primitives::Uint<256, 4> =
        storage_address_deposit + U256::from(storage_proof.index);

    let deposit_storage_key_bytes = deposit_storage_key.to_be_bytes::<32>();

    if deposit_storage_key_bytes != deposit_storage_proof.key.as_b256().0 {
        panic!(
            "Invalid deposit storage key. left: {:?} right: {:?}",
            deposit_storage_key_bytes,
            deposit_storage_proof.key.as_b256().0
        );
    }

    if storage_key.to_be_bytes() != utxo_storage_proof.key.as_b256().0 {
        panic!(
            "Invalid withdrawal UTXO storage key. left: {:?} right: {:?}",
            storage_key.to_be_bytes::<32>(),
            utxo_storage_proof.key.as_b256().0
        );
    }

    storage_verify(&deposit_storage_proof, state_root);

    storage_verify(&utxo_storage_proof, state_root);

    (
        utxo_storage_proof.value.to_string(),
        deposit_storage_proof.value.to_le_bytes(),
    )
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
    let kaddr = {
        let mut hasher: Sha256 = sha2::Digest::new_with_prefix(ADDRESS.as_slice());
        #[allow(clippy::unnecessary_fallible_conversions)]
        hasher.update(
            U256::try_from(storage_proof.key.as_b256())
                .unwrap()
                .as_le_slice(),
        );
        let arr = hasher.finalize();
        U256::from_le_slice(&arr)
    };
    let storage_key = [b"E/s/".as_slice(), kaddr.as_le_slice()].concat();
    let key_hash = KeyHash::with::<Sha256>(storage_key.clone());

    let proved_value = if storage_proof.proof[1] == Bytes::from("y") {
        // Storage value exists and it's serialized form is:
        let bytes = storage_proof.value.as_le_bytes().to_vec();
        Some(bytes)
    } else {
        // Storage value does not exist
        panic!("storage does not exist");
    };

    let storage_proof: jmt::proof::SparseMerkleProof<Sha256> =
        borsh::from_slice(&storage_proof.proof[0]).unwrap();

    let expected_root_hash = jmt::RootHash(expected_root_hash);

    storage_proof
        .verify(expected_root_hash, key_hash, proved_value)
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
            hex::decode("18f3fda28dd327044edc9ff0054ab2a51d6e36edb77a8b8ab028217f90221a5b")
                .expect("Valid hex, cannot fail")
                .try_into()
                .expect("Valid length, cannot fail");

        let (user_wd_outpoint_str, move_tx_id) = verify_storage_proofs(&storage_proof, state_root);

        let move_tx_id_hex = hex::encode(move_tx_id);

        let user_wd_outpoint_bytes = num_bigint::BigUint::from_str(&user_wd_outpoint_str)
            .unwrap()
            .to_bytes_be();

        let expected_user_wd_outpoint_bytes = [
            147, 207, 2, 221, 145, 156, 136, 149, 25, 238, 110, 211, 245, 51, 30, 237, 238, 245,
            129, 239, 223, 144, 127, 37, 107, 63, 161, 147, 23, 142, 87, 91,
        ];

        let expected_move_tx_id_hex =
            "26dd4180932d8071705bc01fe52c11b6d0512c6eaf9847ccea822307934c3492";

        assert_eq!(
            move_tx_id_hex, expected_move_tx_id_hex,
            "Invalid transaction ID"
        );

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
            hex::decode("18f3fda28dd327044edc9ff0054ab2a51d6e36edb77a8b8ab028217f90221a5b")
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
            hex::decode("18f3fda28dd327044edc9ff0054ab2a51d6e36edb77a8b8ab028217f90221a5a")
                .expect("Valid hex, cannot fail")
                .try_into()
                .expect("Valid length, cannot fail");

        verify_storage_proofs(&storage_proof, state_root);
    }
}
