use super::{CitreaClient, CitreaClientT, LightClientProverRpcClient};
use crate::config::protocol::{ProtocolParamset, ProtocolParamsetExt};
use circuits_lib::bridge_circuit::lc_proof::check_method_id;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use clementine_errors::BridgeError;
use eyre::Context;
use risc0_zkvm::{compute_image_id, ExecutorEnv, ProverOpts, Receipt};

const CITREA_MAINNET_LCP_ELF: &[u8] = include_bytes!(concat!(
    "../../../resources/guests/risc0/mainnet/light-client-proof-0.bin"
));
const CITREA_TESTNET_LCP_ELF: &[u8] = include_bytes!(concat!(
    "../../../resources/guests/risc0/testnet/light-client-proof-1.bin"
));
const CITREA_DEVNET_LCP_ELF: &[u8] = include_bytes!(concat!(
    "../../../resources/guests/risc0/devnet/light-client-proof-1.bin"
));

fn resolve_citrea_lcp_elf(paramset: &ProtocolParamset) -> Result<Vec<u8>, BridgeError> {
    let elf = match paramset.network {
        bitcoin::Network::Bitcoin => CITREA_MAINNET_LCP_ELF,
        bitcoin::Network::Testnet4 => CITREA_TESTNET_LCP_ELF,
        bitcoin::Network::Signet => CITREA_DEVNET_LCP_ELF,
        // Citrea's TestNetworkWithForks path uses LIGHT_CLIENT_LATEST_BITCOIN_GUESTS.
        bitcoin::Network::Regtest => citrea_risc0_light_client::LIGHT_CLIENT_PROOF_BITCOIN_ELF,
        _ => return Err(BridgeError::UnsupportedNetwork),
    };

    if elf.is_empty() {
        return Err(eyre::eyre!("Citrea LCP ELF is empty").into());
    }

    Ok(elf.to_vec())
}

pub(super) async fn prove_light_client_proof_locally(
    citrea_client: &CitreaClient,
    l1_height: u64,
    paramset: &'static ProtocolParamset,
) -> Result<Receipt, BridgeError> {
    if l1_height > 0 {
        citrea_client
            .get_light_client_proof(l1_height - 1, paramset)
            .await?
            .ok_or_else(|| {
                eyre::eyre!(
                    "Previous light client proof not found for block height {}",
                    l1_height - 1
                )
            })?;
    }

    let circuit_input = citrea_client
        .light_client_prover_client
        .create_light_client_circuit_input(l1_height)
        .await
        .wrap_err("Failed to create light client circuit input")?;

    if circuit_input.l1_height != l1_height {
        return Err(eyre::eyre!(
            "Light client circuit input height mismatch: expected {}, got {}",
            l1_height,
            circuit_input.l1_height
        )
        .into());
    }

    let lcp_elf = resolve_citrea_lcp_elf(paramset)?;
    let expected_lc_image_id = paramset.get_lcp_image_id()?;
    let actual_lc_image_id = compute_image_id(&lcp_elf)
        .map_err(|e| eyre::eyre!("Failed to compute Citrea LCP ELF image ID: {}", e))?
        .as_bytes()
        .to_owned();
    if actual_lc_image_id != expected_lc_image_id {
        return Err(eyre::eyre!(
            "Citrea LCP ELF image ID mismatch: expected {}, got {}",
            hex::encode(expected_lc_image_id),
            hex::encode(actual_lc_image_id)
        )
        .into());
    }

    let expected_l1_hash = circuit_input.l1_hash;
    let input_bytes = circuit_input.input;
    let receipt = tokio::task::spawn_blocking(move || -> Result<Receipt, eyre::Report> {
        let env = ExecutorEnv::builder()
            .write_slice(&input_bytes)
            .build()
            .map_err(|e| eyre::eyre!("Failed to build LCP proving environment: {}", e))?;

        let prover = risc0_zkvm::default_prover();
        prover
            .prove_with_opts(env, &lcp_elf, &ProverOpts::succinct())
            .map_err(|e| eyre::eyre!("Failed to locally prove light client proof: {}", e))
            .map(|result| result.receipt)
    })
    .await
    .map_err(|e| eyre::eyre!("Failed to join local LCP proving task: {}", e))??;

    validate_light_client_receipt(&receipt, paramset, expected_l1_hash)?;

    Ok(receipt)
}

fn validate_light_client_receipt(
    receipt: &Receipt,
    paramset: &ProtocolParamset,
    expected_l1_hash: [u8; 32],
) -> Result<LightClientCircuitOutput, BridgeError> {
    let expected_lc_image_id = paramset.get_lcp_image_id()?;
    let proof_output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
        .wrap_err("Failed to deserialize light client circuit output")?;

    if !paramset.is_regtest() {
        receipt
            .verify(expected_lc_image_id)
            .map_err(|_| eyre::eyre!("Light client proof verification failed"))?;

        if !check_method_id(&proof_output, expected_lc_image_id) {
            return Err(eyre::eyre!(
                "Current light client proof method ID does not match the expected LC image ID"
            )
            .into());
        }
    }

    if proof_output.latest_da_state.block_hash != expected_l1_hash {
        return Err(eyre::eyre!(
            "Light client proof L1 hash mismatch: expected {}, got {}",
            hex::encode(expected_l1_hash),
            hex::encode(proof_output.latest_da_state.block_hash)
        )
        .into());
    }

    Ok(proof_output)
}
