use super::structs::LightClientProof;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use risc0_zkvm::guest::env;

pub const LC_IMAGE_ID: [u32; 8] = [
    3660459984, 67963468, 224607921, 1061011534, 1677575514, 2989077152, 2727382595, 2335204203,
];

/// Verifies the light client proof and returns the light client circuit output.
pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> LightClientCircuitOutput {
    let light_client_circuit_output: LightClientCircuitOutput =
        borsh::from_slice(light_client_proof.lc_journal.as_slice())
            .expect("Failed to deserialize light client circuit output");

    env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal).unwrap();

    assert_eq!(
        light_client_circuit_output.light_client_proof_method_id, LC_IMAGE_ID,
        "Light client proof method ID does not match expected LC_IMAGE_ID"
    );

    light_client_circuit_output
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_zkvm::Receipt;

    #[test]
    fn test_lc_proof_verifier() {
        let lcp_receipt_bytes = include_bytes!("../../test_data/lcp_receipt.bin");
        let lcp_receipt: Receipt = bincode::deserialize(lcp_receipt_bytes).unwrap();

        let light_client_proof: LightClientProof = LightClientProof {
            l2_height: "0x0".to_string(),
            lc_journal: lcp_receipt.journal.bytes.to_vec(),
        };

        let light_client_circuit_output = lc_proof_verifier(light_client_proof);

        let expected_state_root =
            "20476f2cc8568476d4ca3c2e34d2f9889c1cce06289873ed5ed46c31be0ce55e";
        let expected_last_block_hash =
            "cdac10c915210c36f5b182eed334c0834a616302f1a393a3bcbfc2303b030000";

        assert_eq!(
            hex::encode(light_client_circuit_output.l2_state_root),
            expected_state_root
        );
        assert_eq!(
            hex::encode(light_client_circuit_output.latest_da_state.block_hash),
            expected_last_block_hash
        );
    }
}
