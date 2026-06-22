use super::{CitreaClient, LightClientProverRpcClient};
use crate::{citrea::LightClientCircuitInputRpcResponse, errors::BridgeError};
use crate::config::protocol::ProtocolParamset;
use circuits_lib::bridge_circuit::lc_proof::check_method_id;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use eyre::Context;
use risc0_zkvm::{
    compute_image_id, ExecutorEnv, LocalProver, Prover, ProverOpts, Receipt, VerifierContext,
};

const DEFAULT_LCP_SEGMENT_LIMIT_PO2: u32 = 20;
const LCP_SEGMENT_LIMIT_PO2_ENV: &str = "LCP_SEGMENT_LIMIT_PO2";

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

fn apply_lcp_segment_limit(builder: &mut risc0_zkvm::ExecutorEnvBuilder<'_>) {
    let limit = std::env::var(LCP_SEGMENT_LIMIT_PO2_ENV)
        .map(|limit| {
            limit
                .parse()
                .expect("LCP_SEGMENT_LIMIT_PO2 should be a u32")
        })
        .unwrap_or(DEFAULT_LCP_SEGMENT_LIMIT_PO2);

    builder.segment_limit_po2(limit);
}

pub(super) async fn prove_light_client_proof_from_input(
    circuit_input: LightClientCircuitInputRpcResponse,
    paramset: &'static ProtocolParamset,
) -> Result<Receipt, BridgeError> {
    prove_light_client_proof_from_input_with_opts(
        &circuit_input,
        paramset,
        ProverOpts::succinct(),
        false,
    )
    .await
}

// prove with dev mode to just validate the inputs result in a correct proof
// do not create a real proof, we will only create real proof if challenged
pub(super) async fn validate_light_client_circuit_input(
    circuit_input: &LightClientCircuitInputRpcResponse,
    paramset: &'static ProtocolParamset,
) -> Result<(), BridgeError> {
    prove_light_client_proof_from_input_with_opts(
        circuit_input,
        paramset,
        ProverOpts::succinct().with_dev_mode(true),
        true,
    )
    .await?;

    Ok(())
}

async fn prove_light_client_proof_from_input_with_opts(
    circuit_input: &LightClientCircuitInputRpcResponse,
    paramset: &'static ProtocolParamset,
    prover_opts: ProverOpts,
    dev_mode: bool,
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
    let input_bytes = circuit_input.input.clone();
    let receipt = tokio::task::spawn_blocking(move || -> Result<Receipt, eyre::Report> {
        let mut env = ExecutorEnv::builder();
        apply_lcp_segment_limit(&mut env);
        let env = env
            .write_slice(&input_bytes)
            .build()
            .map_err(|e| eyre::eyre!("Failed to build LCP proving environment: {}", e))?;

        if dev_mode {
            LocalProver::new("local")
                .prove_with_opts(env, &lcp_elf, &prover_opts)
                .map_err(|e| eyre::eyre!("Failed to locally prove light client proof: {}", e))
                .map(|result| result.receipt)
        } else {
            risc0_zkvm::default_prover()
                .prove_with_opts(env, &lcp_elf, &prover_opts)
                .map_err(|e| eyre::eyre!("Failed to prove light client proof: {}", e))
                .map(|result| result.receipt)
        }
    })
    .await
    .map_err(|e| eyre::eyre!("Failed to join local LCP proving task: {}", e))??;

    validate_light_client_receipt(&receipt, lcp_image_id, expected_l1_hash, dev_mode)?;

    Ok(receipt)
}

fn validate_light_client_receipt(
    receipt: &Receipt,
    lcp_image_id: [u8; 32],
    expected_l1_hash: [u8; 32],
    dev_mode: bool,
) -> Result<LightClientCircuitOutput, BridgeError> {
    let proof_output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
        .wrap_err("Failed to deserialize light client circuit output")?;

    if dev_mode {
        receipt
            .verify_with_context(
                &VerifierContext::default().with_dev_mode(true),
                lcp_image_id,
            )
            .map_err(|_| eyre::eyre!("Light client proof verification failed"))?;
    } else {
        receipt
            .verify(lcp_image_id)
            .map_err(|_| eyre::eyre!("Light client proof verification failed"))?;
    }

    if proof_output.latest_da_state.block_hash != expected_l1_hash {
        return Err(eyre::eyre!(
            "Light client proof L1 hash mismatch: expected {}, got {}",
            hex::encode(expected_l1_hash),
            hex::encode(proof_output.latest_da_state.block_hash)
        )
        .into());
    }

    if !check_method_id(&proof_output, lcp_image_id) {
        return Err(eyre::eyre!(
            "Light client proof method ID does not match the expected LC image ID"
        )
        .into());
    }

    Ok(proof_output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::protocol::TESTNET4_TEST_PARAMSET;
    use bitcoin::Network;
    use bridge_circuit_host::receipt_from_inner;
    use circuits_lib::bridge_circuit::lc_proof::check_method_id;
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use risc0_zkvm::InnerReceipt;
    use std::path::Path;
    use std::sync::LazyLock;
    use std::time::Duration;

    const DEFAULT_TESTNET_LCP_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
    const DEFAULT_TESTNET_CITREA_RPC_URL: &str = "https://rpc.testnet.citrea.xyz/";
    const DEFAULT_MAINNET_LCP_URL: &str = "https://light-client-prover.mainnet.citrea.xyz/";
    const DEFAULT_MAINNET_CITREA_RPC_URL: &str = "https://rpc.mainnet.citrea.xyz/";
    const MAINNET_FIXED_PROOF_HEIGHT: u64 = 954_256;

    static MAINNET_TEST_PARAMSET: LazyLock<ProtocolParamset> = LazyLock::new(|| ProtocolParamset {
        network: Network::Bitcoin,
        ..TESTNET4_TEST_PARAMSET.clone()
    });

    #[tokio::test]
    #[ignore = "hits public Citrea testnet RPCs and proves the next LCP in RISC0 dev mode"]
    async fn public_testnet_lcp_input_can_prove_next_block() -> Result<(), BridgeError> {
        // Public testnet LCP proofs may be RISC0 dev-mode receipts. Run this
        // ignored test with RISC0_DEV_MODE=1.
        public_lcp_input_can_prove_next_block(
            "testnet",
            DEFAULT_TESTNET_LCP_URL,
            DEFAULT_TESTNET_CITREA_RPC_URL,
            &TESTNET4_TEST_PARAMSET,
            None,
        )
        .await
    }

    #[tokio::test]
    #[ignore = "hits public Citrea mainnet RPCs and proves the next LCP; requires RISC0_DEV_MODE=0"]
    async fn public_mainnet_lcp_input_can_prove_next_block() -> Result<(), BridgeError> {
        // Mainnet requires RISC0_DEV_MODE=0 because this test generates and
        // verifies a real LCP receipt.
        public_lcp_input_can_prove_next_block(
            "mainnet",
            DEFAULT_MAINNET_LCP_URL,
            DEFAULT_MAINNET_CITREA_RPC_URL,
            &MAINNET_TEST_PARAMSET,
            Some(MAINNET_FIXED_PROOF_HEIGHT),
        )
        .await
    }

    async fn public_lcp_input_can_prove_next_block(
        network_name: &str,
        lcp_url: &str,
        citrea_rpc_url: &str,
        paramset: &'static ProtocolParamset,
        fixed_proof_height: Option<u64>,
    ) -> Result<(), BridgeError> {
        let proof_height = match fixed_proof_height {
            Some(height) => {
                println!("Using fixed {network_name} L1 proof height {height}");
                height
            }
            None => {
                let height = latest_l1_height(network_name, citrea_rpc_url).await?;
                println!("Latest {network_name} L1 height is {height}");
                height
            }
        };
        let input_height = proof_height + 1;

        let lcp_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(120))
            .build(lcp_url)
            .wrap_err_with(|| format!("Failed to create public {network_name} LCP RPC client"))?;

        let previous_proof = lcp_client
            .get_light_client_proof_by_l1_height(proof_height)
            .await
            .wrap_err_with(|| format!("Failed to fetch public {network_name} LCP proof"))?
            .ok_or_else(|| {
                eyre::eyre!("Public {network_name} LCP proof not found at L1 height {proof_height}")
            })?;

        let previous_receipt = receipt_from_inner(
            bincode::deserialize::<InnerReceipt>(&previous_proof.proof).wrap_err_with(|| {
                format!("Failed to deserialize public {network_name} LCP proof")
            })?,
        )
        .wrap_err_with(|| {
            format!("Failed to create receipt from public {network_name} LCP proof")
        })?;
        let expected_lcp_image_id = paramset.get_lcp_image_id()?;
        previous_receipt
            .verify(expected_lcp_image_id)
            .wrap_err_with(|| format!("Public {network_name} LCP proof verification failed"))?;
        let previous_output: LightClientCircuitOutput =
            borsh::from_slice(&previous_receipt.journal.bytes).wrap_err_with(|| {
                format!("Failed to deserialize public {network_name} LCP output")
            })?;
        if !check_method_id(&previous_output, expected_lcp_image_id) {
            return Err(eyre::eyre!(
                "Public {network_name} LCP proof method ID mismatch at L1 height {proof_height}"
            )
            .into());
        }

        let next_input = LightClientProverRpcClient::create_light_client_circuit_input(
            &lcp_client,
            input_height,
        )
        .await
        .wrap_err_with(|| format!("Failed to fetch public {network_name} next LCP input"))?;
        if next_input.l1_height != input_height {
            return Err(eyre::eyre!(
                "Public {network_name} LCP input height mismatch: expected {}, got {}",
                input_height,
                next_input.l1_height
            )
            .into());
        }

        let next_receipt = prove_light_client_proof_from_input(next_input, paramset).await?;
        let next_output: LightClientCircuitOutput = borsh::from_slice(&next_receipt.journal.bytes)
            .wrap_err_with(|| {
                format!("Failed to deserialize locally proved public {network_name} LCP output")
            })?;
        if !check_method_id(&next_output, expected_lcp_image_id) {
            return Err(eyre::eyre!(
                "Locally proved public {network_name} LCP method ID mismatch at L1 height {input_height}"
            )
            .into());
        }

        save_lcp_artifacts_if_requested(network_name, input_height, &next_receipt)?;

        Ok(())
    }

    fn save_lcp_artifacts_if_requested(
        network_name: &str,
        l1_height: u64,
        receipt: &Receipt,
    ) -> Result<(), BridgeError> {
        let Ok(output_dir) = std::env::var("LCP_PROOF_OUTPUT_DIR") else {
            return Ok(());
        };

        let output_dir = Path::new(&output_dir);
        std::fs::create_dir_all(output_dir)
            .wrap_err_with(|| format!("Failed to create LCP output dir {output_dir:?}"))?;

        let receipt_path = output_dir.join(format!("{network_name}-l1-{l1_height}-receipt.bin"));
        let journal_path = output_dir.join(format!("{network_name}-l1-{l1_height}-journal.bin"));

        std::fs::write(
            &receipt_path,
            borsh::to_vec(receipt).wrap_err("Failed to serialize LCP receipt")?,
        )
        .wrap_err_with(|| format!("Failed to write LCP receipt to {receipt_path:?}"))?;
        std::fs::write(&journal_path, &receipt.journal.bytes)
            .wrap_err_with(|| format!("Failed to write LCP journal to {journal_path:?}"))?;

        println!("Saved LCP receipt to {}", receipt_path.display());
        println!("Saved LCP journal to {}", journal_path.display());

        Ok(())
    }

    async fn latest_l1_height(
        network_name: &str,
        citrea_rpc_url: &str,
    ) -> Result<u64, BridgeError> {
        let citrea_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(30))
            .build(citrea_rpc_url)
            .wrap_err_with(|| {
                format!("Failed to create public {network_name} Citrea RPC client")
            })?;
        let height: String = citrea_client
            .request("ledger_getLastScannedL1Height", rpc_params![])
            .await
            .wrap_err_with(|| {
                format!("Failed to fetch public {network_name} latest scanned L1 height")
            })?;

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
