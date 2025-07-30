use super::structs::LightClientProof;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use risc0_zkvm::guest::env;

// use risc0_zkvm::guest::env;

const LC_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("95d94770d8aa1803f1e63d373b92319b024c1db5d79aad0e78bcf0984c75e813");

pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> LightClientCircuitOutput {
    env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal).unwrap();

    if light_client_proof.lc_journal.len() < 32 {
        panic!("Invalid light client journal");
    }

    let light_client_circuit_output: LightClientCircuitOutput =
        borsh::from_slice(light_client_proof.lc_journal.as_slice())
            .expect("Failed to deserialize light client circuit output");

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

        lcp_receipt.verify(LC_IMAGE_ID).unwrap();

        let light_client_circuit_output: LightClientCircuitOutput =
            borsh::from_slice(light_client_proof.lc_journal.as_slice())
                .expect("Failed to deserialize light client circuit output");

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
