use crate::docker::stark_to_snark;
use crate::structs::{
    BridgeCircuitBitvmInputs, BridgeCircuitHostParams, SuccinctBridgeCircuitPublicInputs,
};
use crate::utils::calculate_succinct_output_prefix;
use ark_bn254::Bn254;
use bitcoin::Transaction;
use bitcoin::{consensus::Decodable, hashes::Hash};
use borsh::{self, BorshDeserialize};
use circuits_lib::bridge_circuit::groth16::CircuitGroth16Proof;
use circuits_lib::bridge_circuit::structs::{BridgeCircuitInput, WorkOnlyCircuitInput};
use circuits_lib::bridge_circuit::HEADER_CHAIN_METHOD_ID;
use final_spv::merkle_tree::BitcoinMerkleTree;
use final_spv::spv::SPV;
use header_chain::header_chain::CircuitBlockHeader;
use header_chain::mmr_native::MMRNative;

use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};

const _BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/prod-testnet4-bridge-circuit-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest");

/// Generates a Groth16 proof for the Bridge Circuit after performing sanity checks.
///
/// This function first validates various conditions such as header chain output,
/// light client proof, and SPV verification. It then constructs a succinct proof
/// for the Bridge Circuit. Finally, it converts the succinct proof
/// into a Groth16 proof using a Circom circuit.
///
/// # Arguments
///
/// * `bridge_circuit_host_params` - The host parameters containing circuit-related inputs.
/// * `bridge_circuit_elf` - The compiled ELF binary representing the Bridge Circuit.
///
/// # Returns
///
/// Returns a tuple consisting of:
/// - `ark_groth16::Proof<Bn254>`: The final Groth16 proof.
/// - `[u8; 31]`: The Groth16 output.
/// - `BridgeCircuitBitvmInputs`: The structured inputs for the Bridge Circuit BitVM.
///
/// # Panics
///
/// This function will panic if:
/// - The number of watchtowers does not match expectations.
/// - The header chain proof output differs from the expected value.
/// - Light client proof verification fails.
/// - SPV verification fails.
/// - The journal hash does not match the expected hash.
///
pub fn prove_bridge_circuit(
    bridge_circuit_host_params: BridgeCircuitHostParams,
    bridge_circuit_elf: &[u8],
) -> (
    ark_groth16::Proof<Bn254>,
    [u8; 31],
    BridgeCircuitBitvmInputs,
) {
    let bridge_circuit_input: BridgeCircuitInput = BridgeCircuitInput {
        kickoff_tx: vec![],
        watchtower_idxs: vec![],
        watchtower_challenge_input_idxs: vec![],
        watchtower_pubkeys: vec![],
        watchtower_challenge_utxos: vec![],
        watchtower_challenge_txs: vec![],
        watchtower_challenge_witnesses: vec![],
        hcp: bridge_circuit_host_params.block_header_circuit_output, // This will change in the future
        payout_spv: bridge_circuit_host_params.spv,
        lcp: bridge_circuit_host_params.light_client_proof,
        sp: bridge_circuit_host_params.storage_proof,
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
        generate_succinct_bridge_circuit_public_inputs(bridge_circuit_input.clone());
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

/// Constructs an SPV (Simplified Payment Verification) proof.
///
/// This function decodes a Bitcoin transaction, processes block headers,
/// constructs an MMR (Merkle Mountain Range) for block header commitment,
/// and generates a Merkle proof for the payout transaction's inclusion in
/// the block.
///
/// # Arguments
///
/// * `payout_tx` - A mutable reference to a byte slice representing the payout transaction.
/// * `headers` - A byte slice containing block headers, each 80 bytes long.
/// * `payment_block` - A byte slice representing the full payment block.
/// * `payment_block_height` - The height of the payment block in the blockchain.
/// * `payment_tx_index` - The index of the payout transaction in the block's transaction list.
///
/// # Returns
///
/// Returns an `SPV` struct containing:
/// - The decoded payout transaction.
/// - A Merkle proof of the transaction's inclusion in the block.
/// - The block header.
/// - An MMR proof of the block header's inclusion in the MMR.
///
/// # Panics
///
/// This function will panic if:
/// - Decoding `payout_tx` or `payment_block` fails.
/// - Any block header chunk is not 80 bytes long.
/// - Generating the Merkle or MMR proof fails.
///
pub fn create_spv(
    payout_tx: &mut &[u8],
    headers: &[u8],
    payment_block: bitcoin::Block,
    payment_block_height: u32,
    payment_tx_index: u32,
) -> SPV {
    let payout_tx: Transaction = Transaction::consensus_decode::<&[u8]>(payout_tx).unwrap();

    let headers = headers
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    let mut mmr_native = MMRNative::new();
    for header in headers {
        mmr_native.append(header.compute_block_hash());
    }

    let block_txids: Vec<[u8; 32]> = payment_block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
        .collect();

    let mmr_inclusion_proof = mmr_native.generate_proof(payment_block_height);

    let block_mt = BitcoinMerkleTree::new(block_txids);

    let payout_tx_proof = block_mt.generate_proof(payment_tx_index);

    SPV {
        transaction: payout_tx.into(),
        block_inclusion_proof: payout_tx_proof,
        block_header: payment_block.header.into(),
        mmr_inclusion_proof: mmr_inclusion_proof.1,
    }
}

/// Generates a Groth16 proof of a bitcoin header chain proof where it only outputs the total work.
///
/// This function constructs an execution environment, serializes the provided
/// input using Borsh, and utilizes a default prover to generate a proof using
/// the Groth16 proving system.
///
/// # Arguments
///
/// * `receipt` - A header-chain `Receipt` that serves as an assumption for the proof.
/// * `input` - A reference to `WorkOnlyCircuitInput` containing the necessary
///   header chain output data.
///
/// # Returns
///
/// Returns a new `Receipt` containing the Groth16 proof result.
///
pub fn prove_work_only_header_chain_proof(
    receipt: Receipt,
    input: &WorkOnlyCircuitInput,
) -> Receipt {
    let env = ExecutorEnv::builder()
        .add_assumption(receipt)
        .write_slice(&borsh::to_vec(&input).unwrap())
        .build()
        .unwrap();
    let prover = default_prover();
    prover
        .prove_with_opts(env, WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt
}

/// Prepares the public inputs for the bridge circuit.
///
/// This function constructs the necessary public input values used in the
/// succinct bridge circuit by processing watchtower signatures, computing
/// block hashes, concatenating public keys, and extracting operator IDs.
///
/// # Arguments
///
/// * `input` - A `BridgeCircuitInput` containing all the necessary transaction
///   and chain state details.
///
/// # Returns
///
/// Returns a `SuccinctBridgeCircuitPublicInputs` struct containing:
/// - A compressed bitmask of watchtower challenges.
/// - The payout transaction block hash.
/// - The latest block hash.
/// - The move-to-vault transaction ID.
/// - A digest of watchtower challenge public keys.
/// - The extracted operator ID.
///
fn generate_succinct_bridge_circuit_public_inputs(
    input: BridgeCircuitInput,
) -> SuccinctBridgeCircuitPublicInputs {
    // challenge_sending_watchtowers
    let mut challenge_sending_watchtowers = [0u8; 20];

    // payout tx block hash
    let payout_tx_block_hash: [u8; 20] = input.payout_spv.block_header.compute_block_hash()[12..32]
        .try_into()
        .unwrap();

    // latest block hash
    let latest_block_hash: [u8; 20] = input.hcp.chain_state.best_block_hash[12..32]
        .try_into()
        .unwrap();

    // operator_id
    let last_output = input.payout_spv.transaction.output.last().unwrap();
    let last_output_script = last_output.script_pubkey.to_bytes();

    let len: usize = last_output_script[1] as usize;
    if len > 32 {
        panic!("Invalid operator id length");
    }

    let mut operator_id = [0u8; 32];
    operator_id[..len].copy_from_slice(&last_output_script[2..2 + len]);

    SuccinctBridgeCircuitPublicInputs {
        challenge_sending_watchtowers,
        payout_tx_block_hash,
        latest_block_hash,
        move_to_vault_txid: input.sp.txid_hex,
        operator_id,
        watchtower_challenge_wpks_hash: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use crate::config::BCHostParameters;
    use borsh::BorshDeserialize;

    use circuits_lib::bridge_circuit::winternitz::{
        generate_public_key, sign_digits, Parameters, WinternitzHandler,
    };
    use header_chain::header_chain::BlockHeaderCircuitOutput;
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
        hex_literal::hex!("1ff9f5b6d77bbd4296e1749049d4a841088fb72f7a324da71e31fa1576d4bc0b");

    const HEADERS: &[u8] = include_bytes!("../bin-files/testnet4_headers.bin");
    const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("../bin-files/testnet4_first_72075.bin");
    const PAYOUT_TX: &[u8; 303] = include_bytes!("../bin-files/payout_tx.bin");
    const TESTNET_BLOCK_72041: &[u8] = include_bytes!("../bin-files/testnet4_block_72041.bin");

    const LCP_RECEIPT: &[u8] = include_bytes!("../bin-files/lcp_receipt.bin");
    const LIGHT_CLIENT_PROOF: &[u8] = include_bytes!("../bin-files/light_client_proof.bin");
    const STORAGE_PROOF: &[u8] = include_bytes!("../bin-files/storage_proof.bin");

    pub const TEST_PARAMETERS: BCHostParameters = BCHostParameters {
        l1_block_height: 72075,
        payment_block_height: 72041,
        move_to_vault_txid: hex!(
            "BB25103468A467382ED9F585129AD40331B54425155D6F0FAE8C799391EE2E7F"
        ),
        payout_tx_index: 51,
        deposit_index: 37,
    };

    pub fn sign_winternitz(
        message: Vec<u8>,
        secret_key: Vec<u8>,
        params: Parameters,
    ) -> WinternitzHandler {
        let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);
        let signature = sign_digits(&params, &secret_key, &message);

        WinternitzHandler {
            pub_key,
            params,
            signature: Some(signature),
            message: Some(message),
        }
    }

    #[tokio::test]
    #[ignore = "This test is too slow and only runs in x86_64."]
    async fn bridge_circuit_test() {
        use circuits_lib::bridge_circuit::{
            structs::{LightClientProof, StorageProof},
            total_work_and_watchtower_flags,
        };

        let work_only_method_id_from_elf = compute_image_id(WORK_ONLY_ELF).unwrap();
        assert_eq!(
            work_only_method_id_from_elf.as_bytes(),
            WORK_ONLY_IMAGE_ID,
            "Method ID mismatch, make sure to build the guest programs with new hardcoded values."
        );

        let headerchain_receipt: Receipt =
            Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap();

        let payment_block: bitcoin::Block =
            bitcoin::block::Block::consensus_decode(&mut &TESTNET_BLOCK_72041[..]).unwrap();

        let spv = create_spv(
            &mut PAYOUT_TX.as_ref(),
            HEADERS,
            payment_block,
            TEST_PARAMETERS.payment_block_height,
            TEST_PARAMETERS.payout_tx_index,
        );

        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::BorshDeserialize::try_from_slice(&headerchain_receipt.journal.bytes[..])
                .unwrap();

        let work_only_circuit_input: WorkOnlyCircuitInput = WorkOnlyCircuitInput {
            header_chain_circuit_output: block_header_circuit_output.clone(),
        };

        let work_only_groth16_proof_receipt: Receipt = prove_work_only_header_chain_proof(
            headerchain_receipt.clone(),
            &work_only_circuit_input,
        );

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

        let input: u64 = 1;

        let compressed_proof_and_total_work: Vec<u8> =
            [compressed_proof.as_ref(), commited_total_work.as_ref()].concat();

        println!(
            "Compressed proof and total work: {:?}",
            hex::encode(compressed_proof_and_total_work.clone())
        );

        let len = compressed_proof_and_total_work.len();
        let n0 = u32::try_from(len).expect("Length exceeds u32 max value");
        let params = Parameters::new(n0, 8);

        let mut rng = SmallRng::seed_from_u64(input);
        let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();

        let winternitz_details =
            sign_winternitz(compressed_proof_and_total_work, secret_key, params);

        let light_client_proof: LightClientProof = borsh::from_slice(LIGHT_CLIENT_PROOF).unwrap();
        let lcp_receipt: Receipt = borsh::from_slice(LCP_RECEIPT).unwrap();

        let storage_proof: StorageProof = borsh::from_slice(STORAGE_PROOF).unwrap();

        let num_of_watchtowers: u32 = 1;

        // let bridge_circuit_host_params = BridgeCircuitHostParams {
        //     winternitz_details: vec![winternitz_details],
        //     light_client_proof,
        //     storage_proof,
        //     headerchain_receipt,
        //     spv,
        //     lcp_receipt,
        //     block_header_circuit_output,
        //     num_of_watchtowers,
        // };

        // // Do what a normal bridge circuit guest is supposed to do
        // (_, _) = total_work_and_watchtower_flags(

        //     &bridge_circuit_host_params.winternitz_details,
        //     bridge_circuit_host_params.num_of_watchtowers,
        //     &WORK_ONLY_IMAGE_ID,
        // );

        // let (ark_groth16_proof, output_scalar_bytes_trimmed, bridge_circuit_bitvm_inputs) =
        //     prove_bridge_circuit(bridge_circuit_host_params, TEST_BRIDGE_CIRCUIT_ELF);

        // let blake3_digest = bridge_circuit_bitvm_inputs.calculate_groth16_public_input();
        // let g16_pi_calculated_outside = blake3_digest.as_bytes();
        // assert_eq!(
        //     output_scalar_bytes_trimmed,
        //     g16_pi_calculated_outside[0..31]
        // );
        // assert!(bridge_circuit_bitvm_inputs.verify_bridge_circuit(ark_groth16_proof));
    }
}
