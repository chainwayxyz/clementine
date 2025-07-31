use super::structs::LightClientProof;
use citrea_sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use risc0_zkvm::guest::env;

pub const LC_IMAGE_ID: [u8; 32] =
    hex_literal::hex!("d02f2eda4c0a0d04b13e630d4ec03d3f5ac5fd63a0b229b2438e90a26b63308b");

pub fn lc_proof_verifier(light_client_proof: LightClientProof) -> LightClientCircuitOutput {
    env::verify(LC_IMAGE_ID, &light_client_proof.lc_journal).unwrap();

    if light_client_proof.lc_journal.len() < 32 {
        panic!("Invalid light client journal");
    }

    let light_client_circuit_output: LightClientCircuitOutput =
        borsh::from_slice(light_client_proof.lc_journal.as_slice())
            .expect("Failed to deserialize light client circuit output");

    assert!(
        check_method_id(&light_client_circuit_output),
        "Light client proof method ID does not match the expected LC image ID"
    );

    light_client_circuit_output
}

pub fn check_method_id(light_client_circuit_output: &LightClientCircuitOutput) -> bool {
    let light_client_method_id_bytes: [u8; 32] = light_client_circuit_output
        .light_client_proof_method_id
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect::<Vec<u8>>()
        .try_into()
        .expect("Failed to convert light client proof method ID to bytes");

    light_client_method_id_bytes == LC_IMAGE_ID
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

        assert!(
            check_method_id(&light_client_circuit_output),
            "Light client proof method ID does not match the expected LC image ID"
        );

        let expected_state_root =
            "c2703b6d58a7d93198460425be2a1e292cf8d6b04184fbea867ca3ea7efa1165";
        let expected_last_block_hash =
            "6d9663d16b35884803a7345ce6e92e93ebe436cd8b1ebb010f6766c7c9d49670";

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
