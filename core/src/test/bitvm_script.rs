mod tests {
    use bitcoin::hashes::hash160;
    use bitcoin::hashes::Hash;
    use bitvm::signatures::signing_winternitz::WINTERNITZ_MESSAGE_VERIFIER;
    use bitvm::{
        clementine::additional_disprove::{
            create_additional_replacable_disprove_script, validate_assertions_for_additional_script,
        },
        signatures::winternitz::{generate_public_key, Parameters},
    };
    use bridge_circuit_host::structs::BridgeCircuitBitvmInputs;

    pub const BRIDGE_CIRCUIT_BITVM_TEST_INPUTS: BridgeCircuitBitvmInputs =
        BridgeCircuitBitvmInputs {
            payout_tx_block_hash: [
                171, 145, 219, 174, 239, 44, 95, 81, 182, 77, 233, 148, 175, 177, 146, 161, 119,
                61, 44, 98,
            ],
            latest_block_hash: [
                18, 6, 170, 190, 86, 52, 47, 93, 55, 8, 204, 59, 237, 40, 246, 254, 168, 183, 8,
                111,
            ],
            challenge_sending_watchtowers: [
                15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            deposit_constant: [
                33, 89, 238, 181, 40, 137, 174, 16, 33, 60, 154, 141, 145, 173, 28, 218, 8, 235,
                65, 88, 190, 165, 233, 68, 142, 1, 26, 31, 141, 101, 180, 40,
            ],
            combined_method_id: [
                161, 224, 123, 224, 161, 79, 5, 157, 211, 176, 198, 123, 128, 173, 148, 114, 197,
                152, 64, 188, 185, 37, 45, 158, 225, 162, 241, 192, 225, 240, 16, 113,
            ],
        };

    pub const TEST_GROTH16_PUBLIC_INPUT: [u8; 32] = [
        0, 203, 5, 31, 138, 117, 119, 62, 52, 255, 223, 38, 213, 32, 143, 9, 191, 212, 207, 152,
        21, 182, 225, 177, 179, 58, 105, 29, 64, 114, 229, 184,
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
        dummy_challenge_preimages_final[5] = [31u8; 20].into();

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

    #[test]
    fn spendable_by_invalid_payout_block_hash() {
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

        let mut payout_tx_block_hash = BRIDGE_CIRCUIT_BITVM_TEST_INPUTS
            .payout_tx_block_hash
            .to_vec();
        payout_tx_block_hash[0] = 0;

        let payout_tx_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &payout_tx_block_hash_params,
            &payout_tx_block_hash_wsk,
            &payout_tx_block_hash,
        );

        let latest_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &latest_block_hash_params,
            &latest_block_hash_wsk,
            &BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash,
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
            "The script should be spendable by invalid payout tx block hash"
        );
    }

    #[test]
    fn spendable_by_invalid_g16_public_input() {
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

        let mut g16_public_input = BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash.to_vec();
        g16_public_input[1] = 0;

        // Sign the winternitz messages
        let groth16_public_input_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &groth16_public_input_params,
            &groth16_public_input_wsk,
            &g16_public_input,
        );

        let payout_tx_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &payout_tx_block_hash_params,
            &payout_tx_block_hash_wsk,
            &BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.payout_tx_block_hash,
        );

        let latest_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &latest_block_hash_params,
            &latest_block_hash_wsk,
            &BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash,
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
            "The script should be spendable by invalid g16 public input"
        );
    }

    #[test]
    fn spendable_by_invalid_challenge_sending_watchtowers() {
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

        let latest_block_hash_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &latest_block_hash_params,
            &latest_block_hash_wsk,
            &BRIDGE_CIRCUIT_BITVM_TEST_INPUTS.latest_block_hash,
        );

        let mut challenge_sending_watchtowers = BRIDGE_CIRCUIT_BITVM_TEST_INPUTS
            .challenge_sending_watchtowers
            .to_vec();
        challenge_sending_watchtowers[0] = 0;

        let challenge_sending_watchtowers_witness = WINTERNITZ_MESSAGE_VERIFIER.sign(
            &challenge_sending_watchtowers_params,
            &challenge_sending_watchtowers_wsk,
            &challenge_sending_watchtowers,
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
            "The script should be spendable by invalid challenge sending watchtowers"
        );
    }
}
