use crate::docker::{stark_to_bitvm2_g16, stark_to_bitvm2_g16_dev_mode};
use crate::structs::{
    BridgeCircuitBitvmInputs, BridgeCircuitHostParams, SuccinctBridgeCircuitPublicInputs,
};
use crate::utils::calculate_succinct_output_prefix;
use ark_bn254::Bn254;
use bitcoin::Transaction;
use borsh;
use circuits_lib::bridge_circuit::groth16::CircuitGroth16Proof;
use circuits_lib::bridge_circuit::merkle_tree::BitcoinMerkleTree;
use circuits_lib::bridge_circuit::spv::SPV;
use circuits_lib::bridge_circuit::structs::WorkOnlyCircuitInput;
use circuits_lib::bridge_circuit::transaction::CircuitTransaction;

use circuits_lib::common::constants::{
    MAINNET_HEADER_CHAIN_METHOD_ID, REGTEST_HEADER_CHAIN_METHOD_ID, SIGNET_HEADER_CHAIN_METHOD_ID,
    TESTNET4_HEADER_CHAIN_METHOD_ID,
};
use circuits_lib::header_chain::mmr_native::MMRNative;
use risc0_zkvm::{compute_image_id, default_prover, is_dev_mode, ExecutorEnv, ProverOpts, Receipt};

pub const REGTEST_BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/regtest-bridge-circuit-guest.bin");

pub const TESTNET4_BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-bridge-circuit-guest.bin");

pub const MAINNET_BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/mainnet-bridge-circuit-guest.bin");

pub const SIGNET_BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/signet-bridge-circuit-guest.bin");

pub const TESTNET4_HEADER_CHAIN_GUEST_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-header-chain-guest.bin");

pub const MAINNET_HEADER_CHAIN_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/mainnet-header-chain-guest.bin");
pub const TESTNET4_HEADER_CHAIN_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-header-chain-guest.bin");
pub const SIGNET_HEADER_CHAIN_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/signet-header-chain-guest.bin");
pub const REGTEST_HEADER_CHAIN_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/regtest-header-chain-guest.bin");

pub const MAINNET_WORK_ONLY_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/mainnet-work-only-guest.bin");
pub const TESTNET4_WORK_ONLY_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest.bin");
pub const SIGNET_WORK_ONLY_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/signet-work-only-guest.bin");
pub const REGTEST_WORK_ONLY_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/regtest-work-only-guest.bin");

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
    tracing::info!("Starting bridge circuit proof generation");
    let bridge_circuit_input = bridge_circuit_host_params
        .clone()
        .into_bridge_circuit_input();

    let header_chain_proof_output_serialized =
        borsh::to_vec(&bridge_circuit_input.hcp).expect("Could not serialize header chain output");

    if bridge_circuit_input.lcp.lc_journal != bridge_circuit_host_params.lcp_receipt.journal.bytes {
        tracing::error!("Light client proof output mismatch");
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
        tracing::error!("Header chain proof output mismatch");
        panic!("Header chain proof output mismatch");
    }

    let header_chain_method_id = match bridge_circuit_host_params.network {
        bitcoin::Network::Bitcoin => MAINNET_HEADER_CHAIN_METHOD_ID,
        bitcoin::Network::Testnet4 => TESTNET4_HEADER_CHAIN_METHOD_ID,
        bitcoin::Network::Signet => SIGNET_HEADER_CHAIN_METHOD_ID,
        bitcoin::Network::Regtest => REGTEST_HEADER_CHAIN_METHOD_ID,
        _ => panic!("Unsupported network"),
    };

    // Check for headerchain receipt
    if bridge_circuit_host_params
        .headerchain_receipt
        .verify(header_chain_method_id)
        .is_err()
    {
        tracing::error!("Header chain receipt verification failed");
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
        tracing::error!("SPV verification failed");
        panic!("SPV verification failed");
    }

    let public_inputs: SuccinctBridgeCircuitPublicInputs =
        SuccinctBridgeCircuitPublicInputs::new(bridge_circuit_input.clone());

    let journal_hash = public_inputs.host_journal_hash();

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&bridge_circuit_input).unwrap());
    // let env = env.add_assumption(bridge_circuit_host_params.lcp_receipt);
    let env = env.add_assumption(bridge_circuit_host_params.headerchain_receipt);
    let env = env.build().unwrap();
    let prover = default_prover();

    tracing::info!("Checks complete, proving bridge circuit");

    let succinct_receipt = prover
        .prove_with_opts(env, bridge_circuit_elf, &ProverOpts::succinct())
        .unwrap()
        .receipt;

    tracing::info!("Bridge circuit proof generated");

    let succinct_receipt_journal: [u8; 32] =
        succinct_receipt.clone().journal.bytes.try_into().unwrap();

    if *journal_hash.as_bytes() != succinct_receipt_journal {
        panic!("Journal hash mismatch");
    }

    let bridge_circuit_method_id = compute_image_id(bridge_circuit_elf).unwrap();
    let combined_method_id_constant =
        calculate_succinct_output_prefix(bridge_circuit_method_id.as_bytes());
    let (g16_proof, g16_output) = if is_dev_mode() {
        stark_to_bitvm2_g16_dev_mode(succinct_receipt, &succinct_receipt_journal)
    } else {
        stark_to_bitvm2_g16(
            succinct_receipt.inner.succinct().unwrap().clone(),
            &succinct_receipt_journal,
        )
    };

    tracing::info!("Bridge circuit Groth16 proof generated");

    let risc0_g16_seal_vec = g16_proof.to_vec();
    let risc0_g16_256 = risc0_g16_seal_vec[0..256].try_into().unwrap();
    let circuit_g16_proof = CircuitGroth16Proof::from_seal(risc0_g16_256);
    let ark_groth16_proof: ark_groth16::Proof<Bn254> = circuit_g16_proof.into();

    let deposit_constant = public_inputs.deposit_constant.0;
    tracing::debug!("Deposit constant - circuit: {:?}", deposit_constant);

    (
        ark_groth16_proof,
        g16_output,
        BridgeCircuitBitvmInputs {
            payout_tx_block_hash: public_inputs.payout_tx_block_hash.0,
            latest_block_hash: public_inputs.latest_block_hash.0,
            challenge_sending_watchtowers: public_inputs.challenge_sending_watchtowers.0,
            deposit_constant: public_inputs.deposit_constant.0,
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
    payout_tx: Transaction,
    block_hash_bytes: &[[u8; 32]],
    payment_block: bitcoin::Block,
    payment_block_height: u32,
    genesis_block_height: u32,
    payment_tx_index: u32,
) -> SPV {
    let mut mmr_native = MMRNative::new();
    for block_hash in block_hash_bytes {
        mmr_native.append(*block_hash);
    }

    let block_txids: Vec<CircuitTransaction> = payment_block
        .txdata
        .iter()
        .map(|tx| CircuitTransaction(tx.clone()))
        .collect();

    let mmr_inclusion_proof =
        mmr_native.generate_proof(payment_block_height - genesis_block_height);

    let block_mt = BitcoinMerkleTree::new_mid_state(&block_txids);

    let payout_tx_proof = block_mt.generate_proof(payment_tx_index);

    SPV {
        transaction: CircuitTransaction(payout_tx),
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
        .prove_with_opts(env, TESTNET4_WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt
}

#[cfg(test)]
mod tests {

    // use crate::config::BCHostParameters;

    use crate::mock_zkvm::MockZkvmHost;

    use super::*;

    // const TEST_BRIDGE_CIRCUIT_ELF: &[u8] =
    //     include_bytes!("../../risc0-circuits/elfs/test-testnet4-bridge-circuit-guest.bin");

    use borsh::BorshDeserialize;
    use circuits_lib::{
        bridge_circuit::structs::WorkOnlyCircuitOutput,
        common::zkvm::ZkvmHost,
        header_chain::{
            header_chain_circuit, BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader,
            HeaderChainCircuitInput, HeaderChainPrevProofType,
        },
    };

    // ALSO IMPORTANT FOR HEADERCHAIN IMAGE ID BITCOIN_NETWORK SHOULD BE SET TO "testnet4"
    // pub const TESTNET4_WORK_ONLY_IMAGE_ID: [u8; 32] =
    //     hex_literal::hex!("6d104e43b3c55b70a47873edbbd22c8cf01b5fc77e5ff973ad8ba4b9cf3528dc");

    const TESTNET4_HEADERS: &[u8] = include_bytes!("../bin-files/testnet4-headers.bin");
    // const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("../bin-files/testnet4_first_72075.bin");
    // const PAYOUT_TX: &[u8; 303] = include_bytes!("../bin-files/payout_tx.bin");
    // const TESTNET_BLOCK_72041: &[u8] = include_bytes!("../bin-files/testnet4_block_72041.bin");

    // const LCP_RECEIPT: &[u8] = include_bytes!("../bin-files/lcp_receipt.bin");
    // const LIGHT_CLIENT_PROOF: &[u8] = include_bytes!("../bin-files/light_client_proof.bin");
    // const STORAGE_PROOF: &[u8] = include_bytes!("../bin-files/storage_proof.bin");

    // pub const TEST_PARAMETERS: BCHostParameters = BCHostParameters {
    //     l1_block_height: 72075,
    //     payment_block_height: 72041,
    //     move_to_vault_txid: hex_literal::hex!(
    //         "BB25103468A467382ED9F585129AD40331B54425155D6F0FAE8C799391EE2E7F"
    //     ),
    //     payout_tx_index: 51,
    //     deposit_index: 37,
    // };

    #[tokio::test]
    #[ignore = "This test is too slow and only runs in x86_64."]
    async fn bridge_circuit_test() {
        // use circuits_lib::bridge_circuit::{
        //     structs::{LightClientProof, StorageProof},
        //     total_work_and_watchtower_flags,
        // };

        // let testnet4_work_only_method_id_from_elf =
        //     compute_image_id(TESTNET4_WORK_ONLY_ELF).unwrap();
        // assert_eq!(
        //     testnet4_work_only_method_id_from_elf.as_bytes(),
        //     TESTNET4_WORK_ONLY_IMAGE_ID,
        //     "Method ID mismatch, make sure to build the guest programs with new hardcoded values."
        // );

        // let headerchain_receipt: Receipt =
        //     Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap();

        // let payment_block: bitcoin::Block =
        //     bitcoin::block::Block::consensus_decode(&mut &TESTNET_BLOCK_72041[..]).unwrap();

        // let spv = create_spv(
        //     &mut PAYOUT_TX.as_ref(),
        //     HEADERS,
        //     payment_block,
        //     TEST_PARAMETERS.payment_block_height,
        //     TEST_PARAMETERS.payout_tx_index,
        // );

        // let light_client_proof: LightClientProof = borsh::from_slice(LIGHT_CLIENT_PROOF).unwrap();
        // let lcp_receipt: Receipt = borsh::from_slice(LCP_RECEIPT).unwrap();

        // let storage_proof: StorageProof = borsh::from_slice(STORAGE_PROOF).unwrap();

        // let num_of_watchtowers: u32 = 1;

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

    #[test]
    fn test_header_chain_circuit() {
        let value = option_env!("BITCOIN_NETWORK");
        println!("BITCOIN_NETWORK: {:?}", value);
        let headers = TESTNET4_HEADERS
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        let host = MockZkvmHost::new();

        let input = HeaderChainCircuitInput {
            method_id: [0; 8],
            prev_proof: HeaderChainPrevProofType::GenesisBlock(ChainState::genesis_state()),
            block_headers: headers[..4000].to_vec(),
        };
        host.write(&input);
        header_chain_circuit(&host);
        let proof = host.prove([0; 8].as_ref());

        let output = BlockHeaderCircuitOutput::try_from_slice(&proof.journal).unwrap();
        let new_host = MockZkvmHost::new();

        let newinput = HeaderChainCircuitInput {
            method_id: [0; 8],
            prev_proof: HeaderChainPrevProofType::PrevProof(output),
            block_headers: headers[4000..8000].to_vec(),
        };
        new_host.write(&newinput);
        new_host.add_assumption(proof);

        header_chain_circuit(&new_host);

        let new_proof = new_host.prove([0; 8].as_ref());

        let new_output = BlockHeaderCircuitOutput::try_from_slice(&new_proof.journal).unwrap();

        println!("Output: {:?}", new_output);
    }

    #[test]
    #[ignore = "This test is too slow and only runs in x86_64."]
    fn work_only_from_header_chain_test() {
        std::env::set_var("RISC0_DEV_MODE", "1");
        let testnet4_header_chain_method_id_from_elf: [u32; 8] =
            compute_image_id(TESTNET4_HEADER_CHAIN_GUEST_ELF)
                .unwrap()
                .as_words()
                .try_into()
                .unwrap();

        let headers = TESTNET4_HEADERS
            .chunks(80)
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();

        // Prepare the input for the circuit
        let header_chain_input = HeaderChainCircuitInput {
            method_id: testnet4_header_chain_method_id_from_elf,
            prev_proof: HeaderChainPrevProofType::GenesisBlock(ChainState::genesis_state()),
            block_headers: headers[..10].to_vec(),
        };

        let mut binding = ExecutorEnv::builder();
        let env = binding.write_slice(&borsh::to_vec(&header_chain_input).unwrap());
        let env = env.build().unwrap();
        let prover = default_prover();

        let header_chain_receipt = prover
            .prove_with_opts(
                env,
                TESTNET4_HEADER_CHAIN_GUEST_ELF,
                &ProverOpts::succinct(),
            )
            .unwrap()
            .receipt;

        // Extract journal of receipt
        let header_chain_output =
            BlockHeaderCircuitOutput::try_from_slice(&header_chain_receipt.journal.bytes).unwrap();

        println!("Output: {:?}", header_chain_output);

        let work_only_input = circuits_lib::bridge_circuit::structs::WorkOnlyCircuitInput {
            header_chain_circuit_output: header_chain_output.clone(),
        };

        let mut binding = ExecutorEnv::builder();
        let env = binding.write_slice(&borsh::to_vec(&work_only_input).unwrap());
        let env = env.add_assumption(header_chain_receipt);
        let env = env.build().unwrap();
        let prover = default_prover();

        let work_only_prove_info = prover
            .prove_with_opts(env, TESTNET4_WORK_ONLY_ELF, &ProverOpts::groth16())
            .unwrap();

        println!(
            "Work only prove info . receipt: {:?}",
            work_only_prove_info.receipt
        );
        println!(
            "Work only prove info . session stats: {:?}",
            work_only_prove_info.stats
        );

        let groth16_seal = &work_only_prove_info.receipt.inner.groth16().unwrap().seal;
        let seal: [u8; 256] = groth16_seal[0..256].try_into().unwrap();

        // Extract journal of receipt
        let work_only_output = WorkOnlyCircuitOutput::try_from_slice(
            &work_only_prove_info.receipt.journal.bytes.clone(),
        )
        .unwrap();

        println!("Output: {:?}", work_only_output);

        let circuit_g16_proof = CircuitGroth16Proof::from_seal(&seal);
        println!("Circuit G16 proof: {:?}", circuit_g16_proof);
    }
}
