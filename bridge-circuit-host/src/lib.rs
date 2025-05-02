use alloy::primitives::keccak256;
use alloy_primitives::U256;
use alloy_rpc_client::RpcClient;
use alloy_rpc_types::EIP1186AccountProofResponse;
use circuits_lib::bridge_circuit::structs::{LightClientProof, StorageProof};
use eyre::bail;
use hex::decode;
use risc0_zkvm::{InnerReceipt, Receipt};
use serde_json::json;

pub mod bridge_circuit_host;
pub mod config;
pub mod docker;
pub mod mock_zkvm;
pub mod structs;
pub mod utils;

const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000007");

const DEPOSIT_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000008");

const CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

/// Fetches the light client proof for a given L1 block height.
///
/// This function queries an Citrea light client prover RPC endpoint to obtain a light client proof
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
///
/// # Panics
/// This function will panic if:
/// * The RPC response does not contain a valid `"proof"` string.
/// * The proof is not a valid hex string.
/// * The proof cannot be deserialized into `InnerReceipt`.
/// * The receipt cannot be extracted from the `InnerReceipt`.
/// * The RPC response does not contain a valid `"lastL2Height"` string.
///
/// Example:
/// ```rust, ignore
/// use alloy_rpc_client::RpcClient;
/// use alloy_rpc_client::ClientBuilder;
/// use bridge_circuit_host::fetch_light_client_proof;
///
/// const LIGHT_CLIENT_PROVER_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
///
/// #[tokio::main]
/// async fn main() {
///     let light_client_rpc_client =
///         ClientBuilder::default().http(LIGHT_CLIENT_PROVER_URL.parse().unwrap());
///
///     let (light_client_proof, lcp_receipt) =
///         fetch_light_client_proof(72471, light_client_rpc_client)
///             .await
///             .unwrap();
/// }
/// ```
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
/// This function interacts with an Citrea RPC endpoint to retrieve a storage proof,
/// which includes proof details for both the UTXO and the deposit index.
///
/// # Arguments
/// * `l2_height` - A reference to `String` representing the L2 block height. (e.g. "0x123a")
/// * `deposit_index` - A `u32` representing the deposit index.
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
/// Example:
/// ```rust,ignore
/// use alloy_rpc_client::ClientBuilder;
/// use bridge_circuit_host::fetch_storage_proof;
/// use hex_literal::hex;
///
/// const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz/";
///
/// #[tokio::main]
/// async fn main() {
///     let citrea_rpc_client = ClientBuilder::default().http(CITREA_TESTNET_RPC.parse().unwrap());
///
///     let storage_proof = fetch_storage_proof(
///         &"0xabc".to_string(),
///         37,
///         hex!("BB25103468A467382ED9F585129AD40331B54425155D6F0FAE8C799391EE2E7F"),
///         citrea_rpc_client,
///     )
///     .await;
/// }
/// ```
pub async fn fetch_storage_proof(
    l2_height: &String,
    deposit_index: u32,
    client: RpcClient,
) -> eyre::Result<StorageProof> {
    let ind = deposit_index;
    let tx_index: u32 = ind * 2;

    let storage_address_wd_utxo_bytes = keccak256(UTXOS_STORAGE_INDEX);
    let storage_address_wd_utxo: U256 = U256::from_be_bytes(
        <[u8; 32]>::try_from(&storage_address_wd_utxo_bytes[..])
            .expect("Slice with incorrect length"),
    );

    // Storage key address calculation UTXO
    let storage_key_wd_utxo: alloy_primitives::Uint<256, 4> =
        storage_address_wd_utxo + U256::from(tx_index);
    let storage_key_wd_utxo_hex = hex::encode(storage_key_wd_utxo.to_be_bytes::<32>());
    let storage_key_wd_utxo_hex = format!("0x{}", storage_key_wd_utxo_hex);

    // Storage key address calculation Deposit
    let storage_address_deposit_bytes = keccak256(DEPOSIT_STORAGE_INDEX);
    let storage_address_deposit: U256 = U256::from_be_bytes(
        <[u8; 32]>::try_from(&storage_address_deposit_bytes[..])
            .expect("Slice with incorrect length"),
    );

    let storage_key_deposit: alloy_primitives::Uint<256, 4> =
        storage_address_deposit + U256::from(deposit_index);
    let storage_key_deposit_hex = hex::encode(storage_key_deposit.to_be_bytes::<32>());
    let storage_key_deposit_hex = format!("0x{}", storage_key_deposit_hex);

    let request = json!([
        CONTRACT_ADDRESS,
        [storage_key_wd_utxo_hex, storage_key_deposit_hex],
        l2_height
    ]);

    let response: serde_json::Value = client.request("eth_getProof", request).await?;

    let response: EIP1186AccountProofResponse = serde_json::from_value(response)?;

    let serialized_utxo = serde_json::to_string(&response.storage_proof[0])?;

    let serialized_deposit = serde_json::to_string(&response.storage_proof[1])?;

    Ok(StorageProof {
        storage_proof_utxo: serialized_utxo,
        storage_proof_deposit_idx: serialized_deposit,
        index: ind,
    })
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
pub fn receipt_from_inner(inner: InnerReceipt) -> eyre::Result<Receipt> {
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
