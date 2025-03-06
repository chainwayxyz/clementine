use alloy::primitives::keccak256;
use alloy_primitives::U256;
use alloy_rpc_client::RpcClient;
use alloy_rpc_types::EIP1186AccountProofResponse;
use anyhow::bail;
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use circuits_lib::bridge_circuit_core::structs::{LightClientProof, StorageProof};
use config::PARAMETERS;
use hex::decode;
use risc0_zkvm::{InnerReceipt, Receipt};
use serde_json::json;
use utils::{get_ark_verifying_key, reverse_bits_and_copy};

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

    let proof_str = response["proof"].as_str().expect("Proof is not a string")[2..].to_string();

    let bytes = decode(proof_str).expect("Invalid hex");
    let decoded: InnerReceipt = bincode::deserialize(&bytes).expect("Failed to deserialize");
    let receipt = receipt_from_inner(decoded).expect("Failed to create receipt");

    let l2_height = response["lightClientProofOutput"]["lastL2Height"]
        .as_str()
        .expect("l2 height is not a string");
    println!("L2 height: {:?}", l2_height);

    Ok((
        LightClientProof {
            lc_journal: receipt.journal.bytes.clone(),
            l2_height: l2_height.to_string(),
        },
        receipt,
    ))
}

pub async fn fetch_storage_proof(l2_height: &String, client: RpcClient) -> StorageProof {
    let ind = PARAMETERS.deposit_index;
    let tx_index: u32 = ind * 2;

    let storage_address_bytes = keccak256(UTXOS_STORAGE_INDEX);
    println!("Storage address: {:?}", &storage_address_bytes[..]);
    let storage_address: U256 = U256::from_be_bytes(
        <[u8; 32]>::try_from(&storage_address_bytes[..]).expect("Slice with incorrect length"),
    );
    let storage_key: alloy_primitives::Uint<256, 4> = storage_address + U256::from(tx_index);
    let storage_key_hex = hex::encode(storage_key.to_be_bytes::<32>());
    println!("Storage key: {:?}", &storage_key_hex);
    let storage_key_hex = format!("0x{}", storage_key_hex);

    let concantenated = [PARAMETERS.move_to_vault_txid, DEPOSIT_MAPPING_STORAGE_INDEX].concat();

    let storage_address_deposit = keccak256(concantenated);
    let storage_address_deposit_hex = hex::encode(storage_address_deposit);
    let storage_address_deposit_hex = format!("0x{}", storage_address_deposit_hex);
    println!(
        "Storage address deposit: {:?}",
        &storage_address_deposit_hex
    );

    let request = json!([
        CONTRACT_ADDRESS,
        [storage_key_hex, storage_address_deposit_hex],
        l2_height
    ]);

    let response: serde_json::Value = client.request("eth_getProof", request).await.unwrap();

    let response: EIP1186AccountProofResponse = serde_json::from_value(response).unwrap();

    println!("HOST VALUE INDEX: {:?}", &response.storage_proof[1].value);
    println!("HOST VALUE MOVE TX: {:?}", &response.storage_proof[0].value);

    let serialized_utxo = serde_json::to_string(&response.storage_proof[0]).unwrap();

    let serialized_deposit = serde_json::to_string(&response.storage_proof[1]).unwrap();

    StorageProof {
        storage_proof_utxo: serialized_utxo,
        storage_proof_deposit_idx: serialized_deposit,
        index: ind,
        txid_hex: PARAMETERS.move_to_vault_txid,
    }
}

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

fn verify_bridge_circuit(
    deposit_constant: [u8; 32],
    combined_method_id_constant: [u8; 32],
    payout_tx_blockhash: [u8; 20],
    latest_blockhash: [u8; 20],
    challenge_sending_watchtowers: [u8; 20],
    proof: ark_groth16::Proof<Bn254>,
) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&payout_tx_blockhash);
    hasher.update(&latest_blockhash);
    hasher.update(&challenge_sending_watchtowers);
    let x = hasher.finalize();
    let x_bytes: [u8; 32] = x.try_into().unwrap();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&deposit_constant);
    hasher.update(&x_bytes);
    let y = hasher.finalize();
    let y_bytes: [u8; 32] = y.try_into().unwrap();
    println!("Y bytes (Journal): {:#?}", y_bytes);

    let mut combined_method_id_constant_buf = [0u8; 32];
    let mut journal_buf = [0u8; 32];

    reverse_bits_and_copy(
        &combined_method_id_constant,
        &mut combined_method_id_constant_buf,
    );
    reverse_bits_and_copy(&y_bytes, &mut journal_buf);

    let mut hasher = blake3::Hasher::new();
    hasher.update(&combined_method_id_constant_buf);
    hasher.update(&journal_buf);
    let public_output = hasher.finalize();

    let public_output_bytes: [u8; 32] = public_output.try_into().unwrap();
    println!("Public output bytes: {:#?}", public_output_bytes);
    let public_input_scalar = ark_bn254::Fr::from_be_bytes_mod_order(&public_output_bytes[0..31]);
    println!("Public input scalar: {:#?}", public_input_scalar);

    let ark_vk = get_ark_verifying_key();
    let ark_pvk = ark_groth16::prepare_verifying_key(&ark_vk);

    ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(&ark_pvk, &proof, &[public_input_scalar])
        .unwrap()
}
