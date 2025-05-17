mod tests {
    use bitcoin::hashes::hash160;
    use bitcoin::hashes::Hash;
    use bitvm::{
        clementine::additional_disprove::{
            create_additional_replacable_disprove_script, validate_assertions_for_additional_script,
        },
        signatures::{
            winternitz::{generate_public_key, Parameters},
            winternitz_hash::WINTERNITZ_MESSAGE_VERIFIER,
        },
    };
    use bridge_circuit_host::structs::BridgeCircuitBitvmInputs;

    pub const BRIDGE_CIRCUIT_BITVM_TEST_INPUTS: BridgeCircuitBitvmInputs =
        BridgeCircuitBitvmInputs {
            payout_tx_block_hash: [
                203, 228, 88, 12, 216, 97, 185, 239, 128, 152, 124, 141, 167, 201, 168, 8, 0, 0, 0,
                0,
            ],
            latest_block_hash: [
                56, 162, 176, 248, 13, 89, 137, 198, 242, 67, 23, 133, 118, 44, 44, 95, 0, 0, 0, 0,
            ],
            challenge_sending_watchtowers: [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            deposit_constant: [
                37, 47, 185, 136, 126, 150, 172, 40, 151, 42, 128, 95, 138, 252, 123, 223, 207,
                159, 236, 75, 130, 199, 185, 134, 121, 57, 224, 31, 253, 85, 77, 236,
            ],
            combined_method_id: [
                161, 214, 106, 178, 1, 195, 45, 129, 234, 4, 124, 64, 43, 81, 166, 51, 185, 111,
                172, 129, 211, 127, 207, 223, 13, 108, 142, 45, 246, 110, 108, 230,
            ],
        };

    pub const TEST_GROTH16_PUBLIC_INPUT: [u8; 32] = [
        45, 127, 183, 188, 75, 116, 238, 55, 241, 232, 147, 13, 135, 30, 226, 96, 10, 48, 9, 91,
        249, 188, 153, 6, 233, 73, 155, 178, 190, 156, 247,
        78, // 78 is correct value trimmed in Groth16 public input
    ];

    type BitvmTestEnv = (
        Vec<u8>,
        Parameters,
        Parameters,
        Parameters,
        Parameters,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );

    fn setup_bitvm_test_environment(num_dummy_challenges: usize) -> BitvmTestEnv {
        let groth16_public_input_wsk = vec![1u8; 20];
        let payout_tx_block_hash_wsk = vec![2u8; 20];
        let latest_block_hash_wsk = vec![3u8; 20];
        let challenge_sending_watchtowers_wsk = vec![4u8; 20];

        let groth16_public_input_params = Parameters::new(64, 4);
        let payout_tx_block_hash_params = Parameters::new(40, 4);
        let latest_block_hash_params = Parameters::new(40, 4);
        let challenge_sending_watchtowers_params = Parameters::new(40, 4);

        let groth16_public_input_pk =
            generate_public_key(&groth16_public_input_params, &groth16_public_input_wsk);
        let payout_tx_block_hash_pk =
            generate_public_key(&payout_tx_block_hash_params, &payout_tx_block_hash_wsk);
        let latest_block_hash_pk =
            generate_public_key(&latest_block_hash_params, &latest_block_hash_wsk);
        let challenge_sending_watchtowers_pk = generate_public_key(
            &challenge_sending_watchtowers_params,
            &challenge_sending_watchtowers_wsk,
        );

        let dummy_challenge_preimages = vec![[31u8; 20]; num_dummy_challenges];
        let mut dummy_challenge_hashes: [[u8; 20]; 160] = [[0u8; 20]; 160];
        for (idx, preimage) in dummy_challenge_preimages.iter().enumerate() {
            dummy_challenge_hashes[idx] = *hash160::Hash::hash(preimage.as_ref()).as_byte_array();
        }

        let script = create_additional_replacable_disprove_script(
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.combined_method_id,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.deposit_constant,
            groth16_public_input_pk,
            payout_tx_block_hash_pk,
            latest_block_hash_pk,
            challenge_sending_watchtowers_pk,
            dummy_challenge_hashes.to_vec(),
        );

        (
            script,
            groth16_public_input_params,
            payout_tx_block_hash_params,
            latest_block_hash_params,
            challenge_sending_watchtowers_params,
            groth16_public_input_wsk,
            payout_tx_block_hash_wsk,
            latest_block_hash_wsk,
            challenge_sending_watchtowers_wsk,
        )
    }

    #[test]
    fn test_bitvm_script() {
        let (
            script,
            groth16_public_input_params,
            payout_tx_block_hash_params,
            latest_block_hash_params,
            challenge_sending_watchtowers_params,
            groth16_public_input_wsk,
            payout_tx_block_hash_wsk,
            latest_block_hash_wsk,
            challenge_sending_watchtowers_wsk,
        ) = setup_bitvm_test_environment(1);

        // Sign the winternitz messages
        let groth16_public_input_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &groth16_public_input_params,
            &groth16_public_input_wsk,
            TEST_GROTH16_PUBLIC_INPUT.as_ref(),
        );

        let payout_tx_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &payout_tx_block_hash_params,
            &payout_tx_block_hash_wsk,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS
                .payout_tx_block_hash
                .as_ref(),
        );

        let latest_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &latest_block_hash_params,
            &latest_block_hash_wsk,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash.as_ref(),
        );

        let challenge_sending_watchtowers_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &challenge_sending_watchtowers_params,
            &challenge_sending_watchtowers_wsk,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS
                .challenge_sending_watchtowers
                .as_ref(),
        );

        let dummy_challenge_preimages_final: [Option<[u8; 20]>; 160] = [None; 160];

        let resulting_witness = validate_assertions_for_additional_script(
            script,
            groth16_public_input_witness,
            payout_tx_block_hash_witness,
            latest_block_hash_witness,
            challenge_sending_watchtowers_witness,
            dummy_challenge_preimages_final.to_vec(),
        );

        assert!(resulting_witness.is_none(), "Witness is invalid");
    }

    #[test]
    fn spendable_by_pre_image() {
        let (
            script,
            groth16_public_input_params,
            payout_tx_block_hash_params,
            latest_block_hash_params,
            challenge_sending_watchtowers_params,
            groth16_public_input_wsk,
            payout_tx_block_hash_wsk,
            latest_block_hash_wsk,
            challenge_sending_watchtowers_wsk,
        ) = setup_bitvm_test_environment(160);

        // Sign the winternitz messages
        let groth16_public_input_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &groth16_public_input_params,
            &groth16_public_input_wsk,
            TEST_GROTH16_PUBLIC_INPUT.as_ref(),
        );

        let payout_tx_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &payout_tx_block_hash_params,
            &payout_tx_block_hash_wsk,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS
                .payout_tx_block_hash
                .as_ref(),
        );

        let latest_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &latest_block_hash_params,
            &latest_block_hash_wsk,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash.as_ref(),
        );

        let challenge_sending_watchtowers_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &challenge_sending_watchtowers_params,
            &challenge_sending_watchtowers_wsk,
            BRIDGE_CIRCUIT_BITVM_TEST_INPUTS
                .challenge_sending_watchtowers
                .as_ref(),
        );

        let mut dummy_challenge_preimages_final: [Option<[u8; 20]>; 160] = [None; 160];
        dummy_challenge_preimages_final[1] = [31u8; 20].into();

        let resulting_witness = validate_assertions_for_additional_script(
            script,
            groth16_public_input_witness,
            payout_tx_block_hash_witness,
            latest_block_hash_witness,
            challenge_sending_watchtowers_witness,
            dummy_challenge_preimages_final.to_vec(),
        );

        assert!(
            resulting_witness.is_some(),
            "The script should be spendable by revealed preimage"
        );
    }

    #[test]
    fn spendable_by_invalid_latest_block_hash() {
        let (
            script,
            groth16_public_input_params,
            payout_tx_block_hash_params,
            latest_block_hash_params,
            challenge_sending_watchtowers_params,
            groth16_public_input_wsk,
            payout_tx_block_hash_wsk,
            latest_block_hash_wsk,
            challenge_sending_watchtowers_wsk,
        ) = setup_bitvm_test_environment(160);

        // Sign the winternitz messages
        let groth16_public_input_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &groth16_public_input_params,
            &groth16_public_input_wsk,
            &TEST_GROTH16_PUBLIC_INPUT,
        );

        let payout_tx_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &payout_tx_block_hash_params,
            &payout_tx_block_hash_wsk,
            &BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.payout_tx_block_hash,
        );

        let mut latest_block_hash = BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash.to_vec();
        latest_block_hash[0] = 0;

        let latest_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &latest_block_hash_params,
            &latest_block_hash_wsk,
            &latest_block_hash,
        );

        let challenge_sending_watchtowers_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &challenge_sending_watchtowers_params,
            &challenge_sending_watchtowers_wsk,
            &BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.challenge_sending_watchtowers,
        );

        let dummy_challenge_preimages_final: [Option<[u8; 20]>; 160] = [None; 160];

        let resulting_witness = validate_assertions_for_additional_script(
            script,
            groth16_public_input_witness,
            payout_tx_block_hash_witness,
            latest_block_hash_witness,
            challenge_sending_watchtowers_witness,
            dummy_challenge_preimages_final.to_vec(),
        );

        assert!(
            resulting_witness.is_some(),
            "The script should be spendable by invalid latest block hash"
        );
    }
}
