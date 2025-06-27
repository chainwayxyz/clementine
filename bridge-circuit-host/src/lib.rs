use alloy::primitives::keccak256;
use alloy_primitives::U256;
use alloy_rpc_client::RpcClient;
use alloy_rpc_types::EIP1186AccountProofResponse;
use circuits_lib::bridge_circuit::structs::{LightClientProof, StorageProof};
use eyre::{bail, Context};
use hex::decode;
use risc0_zkvm::{InnerReceipt, Receipt};
use serde_json::json;

pub mod bridge_circuit_host;
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
/// # Errors
/// Returns an error if:
/// * The RPC request fails.
/// * The response does not contain a valid `"proof"` field.
/// * The proof is not a valid hex string.
/// * The proof cannot be deserialized into `InnerReceipt`.
/// * The receipt cannot be extracted from the `InnerReceipt`.
/// * The response does not contain a valid `"lastL2Height"` field.
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
) -> eyre::Result<(LightClientProof, Receipt)> {
    let request = json!({
        "l1_height": l1_height
    });

    let response: serde_json::Value = client
        .request("lightClientProver_getLightClientProofByL1Height", request)
        .await?;

    let raw_proof = response["proof"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("Proof field is missing or not a string"))?;

    let proof_str = raw_proof
        .strip_prefix("0x")
        .ok_or_else(|| eyre::eyre!("Invalid proof format: missing 0x prefix"))?
        .to_string();

    let bytes = decode(proof_str).wrap_err("Failed to decode hex proof")?;

    let decoded: InnerReceipt =
        bincode::deserialize(&bytes).wrap_err("Failed to deserialize proof")?;

    let receipt = receipt_from_inner(decoded)?;

    let l2_height = response["lightClientProofOutput"]["lastL2Height"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("lastL2Height field is missing or not a string"))?;

    Ok((
        LightClientProof {
            lc_journal: receipt.journal.bytes.clone(),
            l2_height: l2_height.to_string(),
        },
        receipt,
    ))
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
