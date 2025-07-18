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
        let lcp_receipt: Receipt = borsh::from_slice(lcp_receipt_bytes).unwrap();

        println!("LCP Receipt: {:?}", lcp_receipt.clone());

        let light_client_proof: LightClientProof = LightClientProof {
            l2_height: "0x0".to_string(),
            lc_journal: lcp_receipt.journal.bytes.to_vec(),
        };

        // Do not use lc_proof_verifier directly in tests, use the function to verify the proof
        lcp_receipt.verify(LC_IMAGE_ID).unwrap();
        let light_client_circuit_output: LightClientCircuitOutput =
            borsh::from_slice(light_client_proof.lc_journal.as_slice())
                .expect("Failed to deserialize light client circuit output");

        let expected_state_root =
            "2da019e05eb9a6ecc4872120ebf1cfb96704cc0cc967a89bd87b2d5da7f6ca07";
        let expected_last_block_hash =
            "a810cea613b869d296816e88f2f5f35165cd78be7b3ec6564cc41f30d3ff8c41";

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
