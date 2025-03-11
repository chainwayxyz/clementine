use crate::docker::stark_to_snark;
use crate::structs::{
    BridgeCircuitBitvmInputs, BridgeCircuitHostParams, SuccinctBridgeCircuitPublicInputs,
};
use crate::utils::calculate_succinct_output_prefix;
use ark_bn254::Bn254;
use borsh;
use circuits_lib::bridge_circuit::HEADER_CHAIN_METHOD_ID;
use circuits_lib::bridge_circuit_common::groth16::CircuitGroth16Proof;
use circuits_lib::bridge_circuit_common::structs::{BridgeCircuitInput, WorkOnlyCircuitInput};
use circuits_lib::bridge_circuit_common::winternitz::verify_winternitz_signature;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use sha2::{Digest, Sha256};

const _BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/prod-testnet4-bridge-circuit-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest");

pub fn prove_bridge_circuit(
    bridge_circuit_host_params: BridgeCircuitHostParams,
    bridge_circuit_elf: &[u8],
) -> (
    ark_groth16::Proof<Bn254>,
    [u8; 31],
    BridgeCircuitBitvmInputs,
) {
    let bridge_circuit_input: BridgeCircuitInput = BridgeCircuitInput {
        winternitz_details: bridge_circuit_host_params.winternitz_details,
        hcp: bridge_circuit_host_params.block_header_circuit_output, // This will change in the future
        payout_spv: bridge_circuit_host_params.spv,
        lcp: bridge_circuit_host_params.light_client_proof,
        sp: bridge_circuit_host_params.storage_proof,
        num_watchtowers: bridge_circuit_host_params.num_of_watchtowers,
    };

    let header_chain_proof_output_serialized =
        borsh::to_vec(&bridge_circuit_input.hcp).expect("Could not serialize header chain output");

    if bridge_circuit_input.lcp.lc_journal != bridge_circuit_host_params.lcp_receipt.journal.bytes {
        panic!("Light client proof output mismatch");
    }

    // if bridge_circuit_host_params.lcp_receipt.verify(LC_IMAGE_ID).is_err()
    // {
    //     panic!("Light client proof receipt verification failed");
    // }

    // Check for number of watchtowers
    if bridge_circuit_input.winternitz_details.len()
        != bridge_circuit_host_params.num_of_watchtowers as usize
    {
        panic!("Number of watchtowers mismatch");
    }

    // Header chain verification
    if header_chain_proof_output_serialized
        != bridge_circuit_host_params.headerchain_receipt.journal.bytes
    {
        panic!("Header chain proof output mismatch");
    }

    // Check for headerchain receipt
    if bridge_circuit_host_params
        .headerchain_receipt
        .verify(HEADER_CHAIN_METHOD_ID)
        .is_err()
    {
        panic!("Header chain receipt verification failed");
    }

    // SPV verification
    if !bridge_circuit_input.payout_spv.verify(
        bridge_circuit_input
            .hcp
            .chain_state
            .block_hashes_mmr
            .clone(),
    ) {
        panic!("SPV verification failed");
    }

    let public_inputs: SuccinctBridgeCircuitPublicInputs =
        public_inputs(bridge_circuit_input.clone());
    let journal_hash = public_inputs.journal_hash();

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&bridge_circuit_input).unwrap());
    // let env = env.add_assumption(bridge_circuit_host_params.lcp_receipt);
    let env = env.add_assumption(bridge_circuit_host_params.headerchain_receipt);
    let env = env.build().unwrap();
    let prover = default_prover();

    tracing::info!("PROVING Bridge CIRCUIT");
    let succinct_receipt = prover
        .prove_with_opts(env, bridge_circuit_elf, &ProverOpts::succinct())
        .unwrap()
        .receipt;

    let succinct_receipt_journal: [u8; 32] = succinct_receipt.journal.bytes.try_into().unwrap();

    if *journal_hash.as_bytes() != succinct_receipt_journal {
        panic!("Journal hash mismatch");
    }

    let bridge_circuit_method_id = compute_image_id(bridge_circuit_elf).unwrap();
    let combined_method_id_constant =
        calculate_succinct_output_prefix(bridge_circuit_method_id.as_bytes());
    let (g16_proof, g16_output) = stark_to_snark(
        succinct_receipt.inner.succinct().unwrap().clone(),
        &succinct_receipt_journal,
    );
    let risc0_g16_seal_vec = g16_proof.to_vec();
    let risc0_g16_256 = risc0_g16_seal_vec[0..256].try_into().unwrap();
    let circuit_g16_proof = CircuitGroth16Proof::from_seal(risc0_g16_256);
    let ark_groth16_proof: ark_groth16::Proof<Bn254> = circuit_g16_proof.into();

    (
        ark_groth16_proof,
        g16_output,
        BridgeCircuitBitvmInputs {
            payout_tx_block_hash: public_inputs.payout_tx_block_hash,
            latest_block_hash: public_inputs.latest_block_hash,
            challenge_sending_watchtowers: public_inputs.challenge_sending_watchtowers,
            deposit_constant: public_inputs.deposit_constant(),
            combined_method_id: combined_method_id_constant,
        },
    )
}

pub fn prove_work_only(receipt: Receipt, input: &WorkOnlyCircuitInput) -> Receipt {
    let mut binding = ExecutorEnv::builder();
    binding.add_assumption(receipt);
    let env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    let env = env.build().unwrap();
    let prover = default_prover();
    prover
        .prove_with_opts(env, WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt
}

fn public_inputs(input: BridgeCircuitInput) -> SuccinctBridgeCircuitPublicInputs {
    // OPTIMIZATION IS POSSIBLE HERE
    // challenge_sending_watchtowers
    let mut watchtower_flags: Vec<bool> = vec![];
    for winternitz_handler in input.winternitz_details.iter() {
        if winternitz_handler.signature.is_none() || winternitz_handler.message.is_none() {
            watchtower_flags.push(false);
            continue;
        }
        let flag = verify_winternitz_signature(winternitz_handler);
        watchtower_flags.push(flag);
    }
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];
    for (i, &flag) in watchtower_flags.iter().enumerate() {
        if flag {
            challenge_sending_watchtowers[i / 8] |= 1 << (i % 8);
        }
    }

    // payout tx block hash
    let payout_tx_block_hash: [u8; 20] = input.payout_spv.block_header.compute_block_hash()[12..32]
        .try_into()
        .unwrap();

    // latest block hash
    let latest_block_hash: [u8; 20] = input.hcp.chain_state.best_block_hash[12..32]
        .try_into()
        .unwrap();

    // watcthower_challenge_wpks_hash
    let num_wts = input.winternitz_details.len();
    let pk_size = input.winternitz_details[0].pub_key.len();

    let mut pub_key_concat: Vec<u8> = vec![0; num_wts * pk_size * 20];
    for (i, wots_handler) in input.winternitz_details.iter().enumerate() {
        for (j, pubkey) in wots_handler.pub_key.iter().enumerate() {
            pub_key_concat[(pk_size * i * 20 + j * 20)..(pk_size * i * 20 + (j + 1) * 20)]
                .copy_from_slice(pubkey);
        }
    }

    let wintertniz_pubkeys_digest: [u8; 32] = Sha256::digest(&pub_key_concat).into();

    // operator_id
    let last_output = input.payout_spv.transaction.output.last().unwrap();
    let last_output_script = last_output.script_pubkey.to_bytes();

    let len: u8 = last_output_script[1];
    let mut operator_id: [u8; 32] = [0u8; 32];
    if len > 32 {
        panic!("Invalid operator id length");
    } else {
        operator_id[..len as usize].copy_from_slice(&last_output_script[2..(2 + len) as usize]);
    }

    SuccinctBridgeCircuitPublicInputs {
        challenge_sending_watchtowers,
        payout_tx_block_hash,
        latest_block_hash,
        move_to_vault_txid: input.sp.txid_hex,
        watcthower_challenge_wpks_hash: wintertniz_pubkeys_digest,
        operator_id,
    }
}

#[cfg(test)]
mod tests {
    use crate::config::BCHostParameters;
    use crate::{fetch_light_client_proof, fetch_storage_proof};
    use alloy_rpc_client::ClientBuilder;
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash;
    use bitcoin::Transaction;
    use borsh::BorshDeserialize;
    use circuits_lib::bridge_circuit::convert_to_groth16_and_verify;
    use circuits_lib::bridge_circuit_common::groth16::CircuitGroth16Proof;
    use circuits_lib::bridge_circuit_common::structs::WorkOnlyCircuitInput;
    use circuits_lib::bridge_circuit_common::winternitz::{
        generate_public_key, sign_digits, Parameters, WinternitzHandler,
    };
    use final_spv::merkle_tree::BitcoinMerkleTree;
    use final_spv::spv::SPV;
    use header_chain::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
    use header_chain::mmr_native::MMRNative;
    use hex_literal::hex;
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};
    use risc0_zkvm::Receipt;
    use std::convert::TryInto;

    use super::*;
    const TEST_BRIDGE_CIRCUIT_ELF: &[u8] =
        include_bytes!("../../risc0-circuits/elfs/test-testnet4-bridge-circuit-guest");
    const WORK_ONLY_ELF: &[u8] =
        include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest");
    pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
        hex_literal::hex!("fbb1477c9c59ab063a7ac59dc5e7432b279f100f3952b607abda00f9346ad736");
    const LIGHT_CLIENT_PROVER_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
    const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz/";

    const HEADERS: &[u8] = include_bytes!("bin-files/testnet4_headers.bin");
    const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("bin-files/testnet4_first_72075.bin");
    const PAYOUT_TX: &[u8; 303] = include_bytes!("bin-files/payout_tx.bin");
    const TESTNET_BLOCK_72041: &[u8] = include_bytes!("bin-files/testnet4_block_72041.bin");

    pub const TEST_PARAMETERS: BCHostParameters = BCHostParameters {
        l1_block_height: 72075,
        payment_block_height: 72041,
        move_to_vault_txid: hex!(
            "BB25103468A467382ED9F585129AD40331B54425155D6F0FAE8C799391EE2E7F"
        ),
        payout_tx_index: 51,
        deposit_index: 37,
    };

    fn create_spv() -> SPV {
        let payout_tx = Transaction::consensus_decode(&mut PAYOUT_TX.as_ref()).unwrap();
        let headers = HEADERS
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();
        let mut mmr_native = MMRNative::new();
        for i in 0..=TEST_PARAMETERS.l1_block_height {
            mmr_native.append(headers[i as usize].compute_block_hash());
        }
        let block_vec = TESTNET_BLOCK_72041.to_vec();
        let block_72041 =
            bitcoin::block::Block::consensus_decode(&mut block_vec.as_slice()).unwrap();

        let block_72041_txids: Vec<[u8; 32]> = block_72041
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
            .collect();
        let mmr_inclusion_proof = mmr_native.generate_proof(TEST_PARAMETERS.payment_block_height);
        let block_72041_mt = BitcoinMerkleTree::new(block_72041_txids);
        let payout_tx_proof = block_72041_mt.generate_proof(TEST_PARAMETERS.payout_tx_index);

        SPV {
            transaction: payout_tx.into(),
            block_inclusion_proof: payout_tx_proof,
            block_header: block_72041.header.into(),
            mmr_inclusion_proof: mmr_inclusion_proof.1,
        }
    }

    fn generate_winternitz(
        compressed_proof: &[u8; 128],
        committed_total_work: &[u8],
    ) -> WinternitzHandler {
        let compressed_proof_and_total_work: Vec<u8> =
            [compressed_proof, committed_total_work].concat();
        println!(
            "Compressed proof and total work: {:?}",
            compressed_proof_and_total_work
        );
        let n0 = compressed_proof_and_total_work.len();
        let log_d = 8;
        let params = Parameters::new(n0.try_into().unwrap(), log_d);
        let input: u64 = 1;
        let mut rng = SmallRng::seed_from_u64(input);
        let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
        let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);
        let signature = sign_digits(&params, &secret_key, &compressed_proof_and_total_work);

        WinternitzHandler {
            pub_key,
            params,
            signature: Some(signature),
            message: Some(compressed_proof_and_total_work),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[tokio::test]
    #[ignore]
    async fn bridge_circuit_test() {
        let work_only_method_id_from_elf = compute_image_id(WORK_ONLY_ELF).unwrap();
        assert_eq!(
            work_only_method_id_from_elf.as_bytes(),
            WORK_ONLY_IMAGE_ID,
            "Method ID mismatch, make sure to build the guest programs with new hardcoded values."
        );
        let citrea_rpc_client = ClientBuilder::default().http(CITREA_TESTNET_RPC.parse().unwrap());
        let light_client_rpc_client =
            ClientBuilder::default().http(LIGHT_CLIENT_PROVER_URL.parse().unwrap());
        let headerchain_receipt: Receipt =
            Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap();
        let spv = create_spv();

        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::BorshDeserialize::try_from_slice(&headerchain_receipt.journal.bytes[..])
                .unwrap();

        let work_only_circuit_input: WorkOnlyCircuitInput = WorkOnlyCircuitInput {
            header_chain_circuit_output: block_header_circuit_output.clone(),
        };

        let work_only_groth16_proof_receipt: Receipt =
            prove_work_only(headerchain_receipt.clone(), &work_only_circuit_input);

        let g16_proof_receipt: &risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> =
            work_only_groth16_proof_receipt.inner.groth16().unwrap();

        let seal =
            CircuitGroth16Proof::from_seal(g16_proof_receipt.seal.as_slice().try_into().unwrap());

        let compressed_proof = seal.to_compressed().unwrap();

        let commited_total_work: [u8; 16] = work_only_groth16_proof_receipt
            .journal
            .bytes
            .try_into()
            .unwrap();

        let winternitz_details = generate_winternitz(&compressed_proof, &commited_total_work);

        let (light_client_proof, lcp_receipt) =
            fetch_light_client_proof(72471, light_client_rpc_client)
                .await
                .unwrap();

        let storage_proof = fetch_storage_proof(
            &light_client_proof.l2_height,
            TEST_PARAMETERS.deposit_index,
            TEST_PARAMETERS.move_to_vault_txid,
            citrea_rpc_client,
        )
        .await;

        let num_of_watchtowers: u32 = 1;

        let bridge_circuit_host_params = BridgeCircuitHostParams {
            winternitz_details: vec![winternitz_details],
            light_client_proof,
            storage_proof,
            headerchain_receipt,
            spv,
            lcp_receipt,
            block_header_circuit_output,
            num_of_watchtowers,
        };
        // Do what a normal bridge circuit guest is supposed to do
        let mut wt_messages_with_idxs: Vec<(usize, Vec<u8>)> = vec![];
        let mut watchtower_flags: Vec<bool> = vec![];
        for (wt_idx, winternitz_handler) in bridge_circuit_host_params
            .winternitz_details
            .iter()
            .enumerate()
        {
            if winternitz_handler.signature.is_none() || winternitz_handler.message.is_none() {
                watchtower_flags.push(false);
                continue;
            }

            let flag = verify_winternitz_signature(winternitz_handler);
            watchtower_flags.push(flag);

            if flag {
                wt_messages_with_idxs.push((wt_idx, winternitz_handler.message.clone().unwrap()));
            }
        }
        wt_messages_with_idxs.sort_by(|a, b| b.1.cmp(&a.1));
        let mut total_work = [0u8; 32];
        for pair in wt_messages_with_idxs.iter() {
            // Grooth16 verification of work only circuit
            if convert_to_groth16_and_verify(&pair.1, &WORK_ONLY_IMAGE_ID) {
                total_work[16..32].copy_from_slice(
                    &pair.1[128..144]
                        .chunks_exact(4)
                        .flat_map(|c| c.iter().rev())
                        .copied()
                        .collect::<Vec<_>>(),
                );
                break;
            }
        }

        let (ark_groth16_proof, output_scalar_bytes_trimmed, bridge_circuit_bitvm_inputs) =
            prove_bridge_circuit(bridge_circuit_host_params, TEST_BRIDGE_CIRCUIT_ELF);

        let blake3_digest = bridge_circuit_bitvm_inputs.calculate_groth16_public_input();
        let g16_pi_calculated_outside = blake3_digest.as_bytes();
        assert_eq!(
            output_scalar_bytes_trimmed,
            g16_pi_calculated_outside[0..31]
        );
        assert!(bridge_circuit_bitvm_inputs.verify_bridge_circuit(ark_groth16_proof));
    }
}
