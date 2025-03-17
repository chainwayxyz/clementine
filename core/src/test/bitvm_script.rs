mod tests {
    use ark_bn254::{g1, Fq, Fq2, Fr, G1Affine, G2Affine};
    use ark_groth16::Proof;
    use bitvm::{
        clementine::additional_disprove::create_additional_replacable_disprove_script,
        groth16,
        signatures::{
            signing_winternitz::WinternitzSecret,
            winternitz::{generate_public_key, Parameters},
        },
    };
    use bridge_circuit_host::structs::BridgeCircuitBitvmInputs;
    use std::str::FromStr;

    use crate::actor::WinternitzDerivationPath;

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
        249, 188, 153, 6, 233, 73, 155, 178, 190, 156, 247, 0,
    ];

    #[test]
    fn test_bitvm_script() {
        let a_x = Fq::from_str(
            "9200088724068355789572279941229918368313641426708727382786962719616623696560",
        )
        .unwrap();
        let a_y = Fq::from_str(
            "14563353130441975199132957338236947117186924631914846970580125360639690219379",
        )
        .unwrap();
        let b0_x = Fq::from_str(
            "18048500302738116963668911405338559380044553199230756036656934549831610304239",
        )
        .unwrap();
        let b1_x = Fq::from_str(
            "10379893452254762731987067546615884571603790017135550584059168089478037642460",
        )
        .unwrap();
        let b0_y = Fq::from_str(
            "1769996193691673917566615861731574458576685315666103534810360405417532175971",
        )
        .unwrap();
        let b1_y = Fq::from_str(
            "8022286857928676168267245467817320225151039658435445221397976193499860200264",
        )
        .unwrap();
        let c_x = Fq::from_str(
            "2713743034426971482822784916204539631335555549549983911994297738839221205439",
        )
        .unwrap();
        let c_y = Fq::from_str(
            "11563664826675727981066602809596721132985602960567235549609006948701685433893",
        )
        .unwrap();
        let b_x = Fq2::new(b0_x, b1_x);
        let b_y = Fq2::new(b0_y, b1_y);

        let a = G1Affine::new(a_x, a_y);
        let b = G2Affine::new(b_x, b_y);
        let c = G1Affine::new(c_x, c_y);

        // Prepare winternitz public keys for g16_public_input, payout_tx_block_hash, latest_block_hash, challenge_sending_watchtowers
        let g16_public_input_wsk = WinternitzSecret::new(32);
        let payout_tx_block_hash_wsk = WinternitzSecret::new(20);
        let latest_block_hash_wsk = WinternitzSecret::new(20);
        let challenge_sending_watchtowers_wsk = WinternitzSecret::new(20);

        let groth16_public_input_params = Parameters::new(32, 8);
        let payout_tx_block_hash_params = Parameters::new(20, 8);
        let latest_block_hash_params = Parameters::new(20, 8);
        let challenge_sending_watchtowers_params = Parameters::new(20, 8);

        let g16_public_input_pk =
            generate_public_key(&groth16_public_input_params, &g16_public_input_wsk);
        let payout_tx_block_hash_pk =
            generate_public_key(&payout_tx_block_hash_params, &payout_tx_block_hash_wsk);
        let latest_block_hash_pk =
            generate_public_key(&latest_block_hash_params, &latest_block_hash_wsk);
        let challenge_sending_watchtowers_pk = generate_public_key(
            &challenge_sending_watchtowers_params,
            &challenge_sending_watchtowers_wsk,
        );

        let a = create_additional_replacable_disprove_script(
            combined_method_id,
            deposit_constant,
            /*Put wpk here*/ payout_tx_block_hash,
        );
    }
}
