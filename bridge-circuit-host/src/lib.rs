use alloy::{
    primitives::keccak256,
    providers::{Provider, ProviderBuilder},
};
use alloy_primitives::U256;
use alloy_rpc_types::EIP1186AccountProofResponse;
use anyhow::bail;
use circuits_lib::bridge_circuit_core::structs::{LightClientProof, StorageProof};
use hex::decode;
use risc0_zkvm::{InnerReceipt, Receipt};
use serde_json::json;

const UTXOS_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000026");
const DEPOSIT_MAPPING_STORAGE_INDEX: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000027");
const TX_ID: [u8; 32] =
    hex_literal::hex!("BB25103468A467382ED9F585129AD40331B54425155D6F0FAE8C799391EE2E7F");

const LIGHT_CLIENT_PROVER_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz/";
const CONTRACT_ADDRESS: &str = "0x3100000000000000000000000000000000000002";

pub async fn fetch_light_client_proof(l1_height: u32) -> Result<(LightClientProof, Receipt), ()> {
    let provider = ProviderBuilder::new().on_http(LIGHT_CLIENT_PROVER_URL.parse().unwrap());
    let client = provider.client();
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

pub async fn fetch_storage_proof(l2_height: &String) -> StorageProof {
    let ind = 37;
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

    let mut concantenated: [u8; 64] = [0; 64];

    concantenated[0..32].copy_from_slice(&TX_ID);
    concantenated[32..64].copy_from_slice(&DEPOSIT_MAPPING_STORAGE_INDEX);

    let storage_address_deposit = keccak256(concantenated);
    let storage_address_deposit_hex = hex::encode(storage_address_deposit);
    let storage_address_deposit_hex = format!("0x{}", storage_address_deposit_hex);
    println!(
        "Storage address deposit: {:?}",
        &storage_address_deposit_hex
    );

    let citrea_provider = ProviderBuilder::new().on_http(CITREA_TESTNET_RPC.parse().unwrap());

    let citrea_client = citrea_provider.client();
    let request = json!([
        CONTRACT_ADDRESS,
        [storage_key_hex, storage_address_deposit_hex],
        l2_height
    ]);

    let response: serde_json::Value = citrea_client
        .request("eth_getProof", request)
        .await
        .unwrap();

    let response: EIP1186AccountProofResponse = serde_json::from_value(response).unwrap();

    println!("HOST VALUE: {:?}", &response.storage_proof[1].value);

    let serialized_utxo = serde_json::to_string(&response.storage_proof[0]).unwrap();

    let serialized_deposit = serde_json::to_string(&response.storage_proof[1]).unwrap();

    StorageProof {
        storage_proof_utxo: serialized_utxo,
        storage_proof_deposit_idx: serialized_deposit,
        index: ind,
        txid_hex: TX_ID,
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
