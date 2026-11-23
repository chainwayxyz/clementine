use crate::errors::BridgeError;
use bridge_circuit_host::sp1::{ensure_assumption, verify};
use circuits_lib::common::programs::ProgramKey;
use circuits_lib::common::sp1::Receipt;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use eyre::Context;

/// Verifies an LCP receipt and binds its journal to the expected DA block.
///
/// Mock receipts are accepted only if `allow_mock` is set, which is the case on every
/// network except mainnet.
pub(super) async fn validate_light_client_receipt(
    receipt: &Receipt,
    lcp_program_key: ProgramKey,
    expected_l1_height: u64,
    expected_l1_hash: [u8; 32],
    allow_mock: bool,
) -> Result<LightClientCircuitOutput, BridgeError> {
    let proof_output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes)
        .wrap_err("Failed to deserialize light client circuit output")?;

    ensure_assumption(receipt)?;
    verify(receipt, lcp_program_key, allow_mock)
        .await
        .map_err(|_| eyre::eyre!("Light client proof verification failed"))?;

    check_lcp_output_binding(
        &proof_output,
        lcp_program_key.recursion,
        expected_l1_height,
        expected_l1_hash,
    )?;

    Ok(proof_output)
}

fn check_lcp_output_binding(
    proof_output: &LightClientCircuitOutput,
    lcp_program_key: [u32; 8],
    expected_l1_height: u64,
    expected_l1_hash: [u8; 32],
) -> Result<(), BridgeError> {
    if proof_output.latest_da_state.block_height != expected_l1_height {
        return Err(eyre::eyre!(
            "Light client proof L1 height mismatch: expected {}, got {}",
            expected_l1_height,
            proof_output.latest_da_state.block_height
        )
        .into());
    }

    if proof_output.latest_da_state.block_hash != expected_l1_hash {
        return Err(eyre::eyre!(
            "Light client proof L1 hash mismatch: expected {}, got {}",
            hex::encode(expected_l1_hash),
            hex::encode(proof_output.latest_da_state.block_hash)
        )
        .into());
    }

    if proof_output.light_client_proof_method_id != lcp_program_key {
        return Err(eyre::eyre!(
            "Light client proof method ID does not match the expected light client program key"
        )
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::citrea::LightClientProverRpcClient;
    use circuits_lib::common::programs::{MAINNET, REGTEST, TESTNET4};
    use circuits_lib::common::sp1::{Groth16Proof, Proof};
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use std::time::Duration;

    const DEFAULT_TESTNET_LCP_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
    const DEFAULT_TESTNET_CITREA_RPC_URL: &str = "https://rpc.testnet.citrea.xyz/";
    const DEFAULT_MAINNET_LCP_URL: &str = "https://light-client-prover.mainnet.citrea.xyz/";
    const MAINNET_FIXED_PROOF_HEIGHT: u64 = 954_256;

    fn fixture_lcp_receipt() -> Receipt {
        borsh::from_slice(include_bytes!(
            "../../../circuits-lib/test_data/lcp_receipt.bin"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn lcp_output_binding_accepts_journal_da_state() {
        let receipt = fixture_lcp_receipt();
        let output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        validate_light_client_receipt(
            &receipt,
            REGTEST.light_client,
            output.latest_da_state.block_height,
            output.latest_da_state.block_hash,
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn lcp_rejects_disallowed_mock_and_groth16_receipts() {
        let mut receipt = fixture_lcp_receipt();
        let output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        let validate = |receipt: Receipt, allow_mock| async move {
            validate_light_client_receipt(
                &receipt,
                REGTEST.light_client,
                output.latest_da_state.block_height,
                output.latest_da_state.block_hash,
                allow_mock,
            )
            .await
        };
        assert!(validate(receipt.clone(), false).await.is_err());

        receipt.inner = Proof::Groth16(Groth16Proof { seal: vec![] });
        let error = validate(receipt, true).await.unwrap_err();
        assert!(error.to_string().contains("compressed"), "{error}");
    }

    #[test]
    fn lcp_output_binding_rejects_mismatched_height_or_hash() {
        let receipt = fixture_lcp_receipt();
        let output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        let program_key = REGTEST.light_client.recursion;

        let err = check_lcp_output_binding(
            &output,
            program_key,
            output.latest_da_state.block_height.wrapping_add(1),
            output.latest_da_state.block_hash,
        )
        .unwrap_err();
        assert!(err.to_string().contains("L1 height mismatch"), "{err:?}");

        let mut wrong_hash = output.latest_da_state.block_hash;
        wrong_hash[0] ^= 0xff;
        let err = check_lcp_output_binding(
            &output,
            program_key,
            output.latest_da_state.block_height,
            wrong_hash,
        )
        .unwrap_err();
        assert!(err.to_string().contains("L1 hash mismatch"), "{err:?}");
    }

    #[tokio::test]
    #[ignore = "hits the public Citrea testnet light client prover; mock proofs are accepted"]
    async fn public_testnet_lcp_verifies() {
        let l1_height = latest_l1_height(DEFAULT_TESTNET_CITREA_RPC_URL).await;
        public_lcp_verifies(
            DEFAULT_TESTNET_LCP_URL,
            l1_height,
            TESTNET4.light_client,
            true,
        )
        .await
    }

    #[tokio::test]
    #[ignore = "hits the public Citrea mainnet light client prover"]
    async fn public_mainnet_lcp_verifies() {
        public_lcp_verifies(
            DEFAULT_MAINNET_LCP_URL,
            MAINNET_FIXED_PROOF_HEIGHT,
            MAINNET.light_client,
            false,
        )
        .await
    }

    /// Fetches a public light client proof and verifies it as an operator does for asserts.
    async fn public_lcp_verifies(
        lcp_url: &str,
        l1_height: u64,
        lcp_program_key: ProgramKey,
        allow_mock: bool,
    ) {
        let lcp_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(120))
            .build(lcp_url)
            .unwrap();
        let proof = lcp_client
            .get_light_client_proof_by_l1_height(l1_height)
            .await
            .unwrap()
            .expect("public light client proof exists");
        let receipt: Receipt = borsh::from_slice(&proof.proof).unwrap();
        let output: LightClientCircuitOutput = borsh::from_slice(&receipt.journal.bytes).unwrap();
        validate_light_client_receipt(
            &receipt,
            lcp_program_key,
            l1_height,
            output.latest_da_state.block_hash,
            allow_mock,
        )
        .await
        .unwrap();
    }

    async fn latest_l1_height(citrea_rpc_url: &str) -> u64 {
        let citrea_client = HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(30))
            .build(citrea_rpc_url)
            .unwrap();
        let height: String = citrea_client
            .request("ledger_getLastScannedL1Height", rpc_params![])
            .await
            .unwrap();
        match height.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).unwrap(),
            None => height.parse().unwrap(),
        }
    }
}
