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
/// A tuple containing:
/// - A `String` representing the verified UTXO value.
/// - A `[u8; 32]` array representing the move-to-vault transaction ID.
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
) -> (String, u32, [u8; 32]) {
    let utxo_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_utxo)
            .expect("Failed to deserialize UTXO storage proof");

    let vout_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_vout)
            .expect("Failed to deserialize vout storage proof");

    let deposit_storage_proof: EIP1186StorageProof =
        serde_json::from_str(&storage_proof.storage_proof_deposit_txid)
            .expect("Failed to deserialize deposit storage proof");

    let storage_address: U256 = {
        let mut keccak = Keccak256::new();
        keccak.update(UTXOS_STORAGE_INDEX);
        let hash = keccak.finalize();
        U256::from_be_bytes(
            <[u8; 32]>::try_from(&hash[..]).expect("Hash slice has incorrect length"),
        )
    };

    let storage_key_utxo: alloy_primitives::Uint<256, 4> =
        storage_address + U256::from(storage_proof.index * 2);

    let storage_key_vout: alloy_primitives::Uint<256, 4> =
        storage_address + U256::from(storage_proof.index * 2 + 1);

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

    if storage_key_utxo.to_be_bytes() != utxo_storage_proof.key.as_b256().0 {
        panic!(
            "Invalid withdrawal UTXO storage key. left: {:?} right: {:?}",
            storage_key_utxo.to_be_bytes::<32>(),
            utxo_storage_proof.key.as_b256().0
        );
    }

    if storage_key_vout.to_be_bytes() != vout_storage_proof.key.as_b256().0 {
        panic!(
            "Invalid withdrawal vout storage key. left: {:?} right: {:?}",
            storage_key_vout.to_be_bytes::<32>(),
            vout_storage_proof.key.as_b256().0
        );
    }

    storage_verify(&utxo_storage_proof, state_root);

    storage_verify(&deposit_storage_proof, state_root);

    storage_verify(&vout_storage_proof, state_root);

    let buf: [u8; 32] = vout_storage_proof.value.to_le_bytes();

    // ENDIANNESS SHOULD BE CHECKED THIS FIELD IS 4 BYTES in the contract

    let vout = u32::from_le_bytes(buf[0..4].try_into().expect("Vout value conversion failed"));

    (
        utxo_storage_proof.value.to_string(),
        vout,
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
    use super::*;
    use std::str::FromStr;

    const STORAGE_PROOF: &[u8] =
        include_bytes!("../../../bridge-circuit-host/bin-files/storage_proof.bin");

    #[test]
    fn test_verify_storage_proofs() {
        let storage_proof: StorageProof = borsh::from_slice(STORAGE_PROOF).unwrap();

        let state_root: [u8; 32] =
            hex::decode("fe1dac365fa622b56c128f75080fbdc226ed087551755ca14c4b4b0287555aa5")
                .expect("Valid hex, cannot fail")
                .try_into()
                .expect("Valid length, cannot fail");

        let (user_wd_outpoint_str, vout, move_tx_id) =
            verify_storage_proofs(&storage_proof, state_root);

        let move_tx_id_hex = hex::encode(move_tx_id);

        let user_wd_outpoint_bytes = num_bigint::BigUint::from_str(&user_wd_outpoint_str)
            .unwrap()
            .to_bytes_be();

        let expected_user_wd_outpoint_bytes = [
            29, 122, 171, 234, 80, 11, 195, 50, 201, 150, 174, 189, 12, 92, 152, 86, 129, 162, 137,
            96, 47, 228, 95, 42, 164, 202, 255, 198, 16, 54, 100, 56,
        ];

        let expected_vout: u32 = 0;

        let expected_move_tx_id_hex =
            "0778b4ccf0c2e2e37d0d6f634f2acb47b22536b935007a137007f88af86d1755";

        assert_eq!(
            move_tx_id_hex, expected_move_tx_id_hex,
            "Invalid transaction ID"
        );

        assert_eq!(
            user_wd_outpoint_bytes, expected_user_wd_outpoint_bytes,
            "Invalid UTXO value"
        );

        assert_eq!(vout, expected_vout, "Invalid vout value");
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
