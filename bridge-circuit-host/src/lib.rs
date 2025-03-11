use alloy::primitives::keccak256;
use alloy_primitives::U256;
use alloy_rpc_client::RpcClient;
use alloy_rpc_types::EIP1186AccountProofResponse;
use anyhow::bail;
use circuits_lib::bridge_circuit::structs::{LightClientProof, StorageProof};
use hex::decode;
use risc0_zkvm::{InnerReceipt, Receipt};
use serde_json::json;

pub mod bridge_circuit_host;
pub mod config;
pub mod docker;
pub mod structs;
pub mod utils;

const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000026");

const DEPOSIT_MAPPING_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000027");

const CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

/// Fetches the light client proof for a given L1 block height.
///
/// This function queries an Ethereum-compatible RPC client to obtain a light client proof
/// for a specified L1 height. The proof is then decoded and deserialized into an `InnerReceipt`,
/// which is further processed to extract a valid `Receipt`.
///
/// # Arguments
/// * `l1_height` - A `u32` representing the L1 block height for which the proof is requested.
/// * `client` - An instance of `RpcClient` used to send the JSON-RPC request.
///
/// # Returns
/// * `Ok((LightClientProof, Receipt))` - A tuple containing:
///   - `LightClientProof`: The extracted proof with journal bytes and L2 height.
///   - `Receipt`: The transaction receipt parsed from the proof.
/// * `Err(())` - If the function encounters an error at any stage.
///
/// # Panics
/// This function will panic if:
/// * The RPC response does not contain a valid `"proof"` string.
/// * The proof is not a valid hex string.
/// * The proof cannot be deserialized into `InnerReceipt`.
/// * The receipt cannot be extracted from the `InnerReceipt`.
/// * The RPC response does not contain a valid `"lastL2Height"` string.
pub async fn fetch_light_client_proof(
    l1_height: u32,
    client: RpcClient,
) -> Result<(LightClientProof, Receipt), ()> {
    let request = json!({
        "l1_height": l1_height
    });

    let response: serde_json::Value = client
        .request("lightClientProver_getLightClientProofByL1Height", request)
        .await
        .unwrap();

    let raw_proof = response["proof"].as_str().expect("Proof is missing");
    let proof_str = raw_proof
        .strip_prefix("0x")
        .expect("Invalid proof format")
        .to_string();

    let bytes = decode(proof_str).expect("Invalid hex");
    let decoded: InnerReceipt = bincode::deserialize(&bytes).expect("Failed to deserialize");
    let receipt = receipt_from_inner(decoded).expect("Failed to create receipt");

    let l2_height = response["lightClientProofOutput"]["lastL2Height"]
        .as_str()
        .expect("l2 height is not a string");

    Ok((
        LightClientProof {
            lc_journal: receipt.journal.bytes.clone(),
            l2_height: l2_height.to_string(),
        },
        receipt,
    ))
}

/// Fetches the storage proof for a given deposit index and transaction ID.
///
/// This function interacts with an Ethereum-compatible RPC client to retrieve a storage proof,
/// which includes proof details for both the UTXO and the deposit index.
///
/// # Arguments
/// * `l2_height` - A reference to `String` representing the L2 block height.
/// * `deposit_index` - A `u32` representing the deposit index.
/// * `move_to_vault_txid` - A 32-byte array representing the transaction ID of the move-to-vault transaction.
/// * `client` - An instance of `RpcClient` used to make the JSON-RPC request.
///
/// # Returns
/// Returns a `StorageProof` struct containing serialized storage proofs for the UTXO and deposit index.
///
/// # Errors
/// * This function will panic if:
///   * `keccak256(UTXOS_STORAGE_INDEX)` does not return a valid 32-byte slice.
///   * The RPC request to `eth_getProof` fails.
///   * The response from the RPC call cannot be deserialized into an `EIP1186AccountProofResponse`.
///
/// # Example
/// ```
/// let client = ClientBuilder::default().http(CITREA_TESTNET_RPC.parse().unwrap());
/// let l2_height = "0x12a";
/// let deposit_index = 42;
/// let txid = [0u8; 32];
///
/// let proof = fetch_storage_proof(l2_height, deposit_index, txid, client).await;
/// ```
pub async fn fetch_storage_proof(
    l2_height: &String,
    deposit_index: u32,
    move_to_vault_txid: [u8; 32],
    client: RpcClient,
) -> StorageProof {
    let ind = deposit_index;
    let tx_index: u32 = ind * 2;

    let storage_address_bytes = keccak256(UTXOS_STORAGE_INDEX);
    let storage_address: U256 = U256::from_be_bytes(
        <[u8; 32]>::try_from(&storage_address_bytes[..]).expect("Slice with incorrect length"),
    );

    // Storage key address calculation UTXO
    let storage_key: alloy_primitives::Uint<256, 4> = storage_address + U256::from(tx_index);
    let storage_key_hex = hex::encode(storage_key.to_be_bytes::<32>());
    let storage_key_hex = format!("0x{}", storage_key_hex);

    // Storage key address calculation Deposit
    let concantenated = [move_to_vault_txid, DEPOSIT_MAPPING_STORAGE_INDEX].concat();
    let storage_address_deposit = keccak256(concantenated);
    let storage_address_deposit_hex = hex::encode(storage_address_deposit);
    let storage_address_deposit_hex = format!("0x{}", storage_address_deposit_hex);

    let request = json!([
        CONTRACT_ADDRESS,
        [storage_key_hex, storage_address_deposit_hex],
        l2_height
    ]);

    let response: serde_json::Value = client.request("eth_getProof", request).await.unwrap();

    let response: EIP1186AccountProofResponse = serde_json::from_value(response).unwrap();

    let serialized_utxo = serde_json::to_string(&response.storage_proof[0]).unwrap();

    let serialized_deposit = serde_json::to_string(&response.storage_proof[1]).unwrap();

    StorageProof {
        storage_proof_utxo: serialized_utxo,
        storage_proof_deposit_idx: serialized_deposit,
        index: ind,
        txid_hex: move_to_vault_txid,
    }
}

/// Converts an `InnerReceipt` into a `Receipt`, ensuring all required fields are present.
///
/// # Arguments
/// * `inner` - The `InnerReceipt` to extract data from.
///
/// # Returns
/// Returns a `Receipt` if all required fields are found, otherwise returns an error.
///
/// # Errors
/// This function can return an error in the following cases:
/// * If `inner.claim()` is empty.
/// * If `claim.value()` is empty.
/// * If `claim.output.value()` is empty.
/// * If `output` is `None`.
/// * If `output.journal.value()` is empty.
///
/// # Example
/// ```
/// let inner_receipt = get_some_inner_receipt(); // Assume this exists
/// let receipt = receipt_from_inner(inner_receipt)?;
/// ```
fn receipt_from_inner(inner: InnerReceipt) -> anyhow::Result<Receipt> {
    let mb_claim = inner.claim().or_else(|_| bail!("Claim is empty"))?;
    let claim = mb_claim
        .value()
        .or_else(|_| bail!("Claim content is empty"))?;
    let output = claim
        .output
        .value()
        .or_else(|_| bail!("Output content is empty"))?;
    let Some(output) = output else {
        bail!("Output body is empty");
    };
    let journal = output
        .journal
        .value()
        .or_else(|_| bail!("Journal content is empty"))?;
    Ok(Receipt::new(inner, journal))
}
