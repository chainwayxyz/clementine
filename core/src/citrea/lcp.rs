use super::{CitreaClient, LightClientProverRpcClient};
use crate::citrea::LightClientCircuitInputRpcResponse;
use crate::config::protocol::{ProtocolParamset, ProtocolParamsetExt};
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
const CITREA_REGTEST_LCP_ELF: &[u8] = include_bytes!(concat!(
    "../../../resources/guests/risc0/regtest/light-client-proof-0.bin"
));

fn resolve_citrea_lcp_elf(paramset: &ProtocolParamset) -> Result<Vec<u8>, BridgeError> {
    let elf = match paramset.network {
        bitcoin::Network::Bitcoin => CITREA_MAINNET_LCP_ELF,
        bitcoin::Network::Testnet4 => CITREA_TESTNET_LCP_ELF,
        bitcoin::Network::Signet => CITREA_DEVNET_LCP_ELF,
        bitcoin::Network::Regtest => CITREA_REGTEST_LCP_ELF,
        _ => return Err(BridgeError::UnsupportedNetwork),
    };

    if elf.is_empty() {
        return Err(eyre::eyre!("Citrea LCP ELF is empty").into());
    }

    Ok(elf.to_vec())
}

pub(super) async fn create_light_client_circuit_input(
    citrea_client: &CitreaClient,
    l1_height: u64,
) -> Result<LightClientCircuitInputRpcResponse, BridgeError> {
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

    if circuit_input.input.is_empty() {
        return Err(eyre::eyre!("Light client circuit input is empty").into());
    }

    Ok(circuit_input)
}

pub(super) async fn prove_light_client_proof_from_input(
    circuit_input: LightClientCircuitInputRpcResponse,
    paramset: &'static ProtocolParamset,
) -> Result<Receipt, BridgeError> {
    let lcp_elf = resolve_citrea_lcp_elf(paramset)?;
    let expected_lc_image_id = paramset.get_lcp_image_id()?;
    let lcp_image_id = compute_image_id(&lcp_elf)
        .map_err(|e| eyre::eyre!("Failed to compute Citrea LCP ELF image ID: {}", e))?
        .as_bytes()
        .try_into()
        .map_err(|_| eyre::eyre!("Citrea LCP ELF image ID is not 32 bytes"))?;
    if lcp_image_id != expected_lc_image_id {
        return Err(eyre::eyre!(
            "Citrea LCP ELF image ID mismatch: expected {}, got {}",
            hex::encode(expected_lc_image_id),
            hex::encode(lcp_image_id)
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

    validate_light_client_receipt(&receipt, lcp_image_id, expected_l1_hash)?;

    Ok(receipt)
}

fn validate_light_client_receipt(
    receipt: &Receipt,
    lcp_image_id: [u8; 32],
    expected_l1_hash: [u8; 32],
) -> Result<LightClientCircuitOutput, BridgeError> {
    let proof_output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
        .wrap_err("Failed to deserialize light client circuit output")?;

    receipt
        .verify(lcp_image_id)
        .map_err(|_| eyre::eyre!("Light client proof verification failed"))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::protocol::{ProtocolParamsetExt, TESTNET4_TEST_PARAMSET};
    use bridge_circuit_host::receipt_from_inner;
    use circuits_lib::bridge_circuit::lc_proof::check_method_id;
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use risc0_zkvm::InnerReceipt;
    use std::time::Duration;

    const DEFAULT_TESTNET_LCP_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
    const DEFAULT_TESTNET_CITREA_RPC_URL: &str = "https://rpc.testnet.citrea.xyz/";

    #[tokio::test]
    #[ignore = "hits public Citrea testnet RPCs and proves the next LCP in RISC0 dev mode"]
    async fn public_testnet_lcp_input_can_prove_next_block() -> Result<(), BridgeError> {
        // Public testnet LCP proofs may be RISC0 dev-mode receipts. Run this
        // ignored test with RISC0_DEV_MODE=1.

        let lcp_url = DEFAULT_TESTNET_LCP_URL;
        let proof_height = latest_testnet_l1_height().await?;
        println!("Latest testnet L1 height is {proof_height}");
        let input_height = proof_height + 1;

        let lcp_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(120))
            .build(&lcp_url)
            .wrap_err("Failed to create public testnet LCP RPC client")?;

        let previous_proof = lcp_client
            .get_light_client_proof_by_l1_height(proof_height)
            .await
            .wrap_err("Failed to fetch public testnet LCP proof")?
            .ok_or_else(|| {
                eyre::eyre!("Public testnet LCP proof not found at L1 height {proof_height}")
            })?;

        let previous_receipt = receipt_from_inner(
            bincode::deserialize::<InnerReceipt>(&previous_proof.proof)
                .wrap_err("Failed to deserialize public testnet LCP proof")?,
        )
        .wrap_err("Failed to create receipt from public testnet LCP proof")?;
        let expected_lcp_image_id = TESTNET4_TEST_PARAMSET.get_lcp_image_id()?;
        previous_receipt
            .verify(expected_lcp_image_id)
            .wrap_err("Public testnet LCP proof verification failed")?;
        let previous_output: LightClientCircuitOutput =
            borsh::from_slice(&previous_receipt.journal.bytes)
                .wrap_err("Failed to deserialize public testnet LCP output")?;
        if !check_method_id(&previous_output, expected_lcp_image_id) {
            return Err(eyre::eyre!(
                "Public testnet LCP proof method ID mismatch at L1 height {proof_height}"
            )
            .into());
        }

        let next_input = LightClientProverRpcClient::create_light_client_circuit_input(
            &lcp_client,
            input_height,
        )
        .await
        .wrap_err("Failed to fetch public testnet next LCP input")?;
        if next_input.l1_height != input_height {
            return Err(eyre::eyre!(
                "Public testnet LCP input height mismatch: expected {}, got {}",
                input_height,
                next_input.l1_height
            )
            .into());
        }

        let next_receipt =
            prove_light_client_proof_from_input(next_input, &TESTNET4_TEST_PARAMSET).await?;
        let next_output: LightClientCircuitOutput = borsh::from_slice(&next_receipt.journal.bytes)
            .wrap_err("Failed to deserialize locally proved public testnet LCP output")?;
        if !check_method_id(&next_output, expected_lcp_image_id) {
            return Err(eyre::eyre!(
                "Locally proved public testnet LCP method ID mismatch at L1 height {input_height}"
            )
            .into());
        }

        Ok(())
    }

    async fn latest_testnet_l1_height() -> Result<u64, BridgeError> {
        let citrea_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(30))
            .build(DEFAULT_TESTNET_CITREA_RPC_URL)
            .wrap_err("Failed to create public testnet Citrea RPC client")?;
        let height: String = citrea_client
            .request("ledger_getLastScannedL1Height", rpc_params![])
            .await
            .wrap_err("Failed to fetch public testnet latest scanned L1 height")?;

        parse_u64(&height)
    }

    fn parse_u64(value: &str) -> Result<u64, BridgeError> {
        if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse()
        }
        .wrap_err_with(|| format!("Failed to parse u64 value {value}"))
        .map_err(Into::into)
    }
}
