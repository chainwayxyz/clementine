use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use borsh::{self, BorshDeserialize};
use bridge_circuit_host::{fetch_light_client_proof, fetch_storage_proof};
use circuits_lib::bridge_circuit_core::groth16::CircuitGroth16Proof;
use circuits_lib::bridge_circuit_core::structs::WorkOnlyCircuitInput;
use circuits_lib::bridge_circuit_core::winternitz::{
    generate_public_key, sign_digits, Parameters, WinternitzCircuitInput, WinternitzHandler,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_to_bitvm2_core::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
use risc0_to_bitvm2_core::merkle_tree::BitcoinMerkleTree;
use risc0_to_bitvm2_core::mmr_native::MMRNative;
use risc0_to_bitvm2_core::spv::SPV;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::convert::TryInto;
use std::fs;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt};

const HEADERS: &[u8] = include_bytes!("bin-files/testnet4_headers.bin");
const TESTNET_BLOCK_47029: &[u8] = include_bytes!("bin-files/testnet4_block_72041.bin");
const BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-bridge-circuit-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest");
const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("bin-files/testnet4_first_72075.bin");
const L1_BLOCK_HEIGHT: u32 = 72075;

const PAYOUT_TX: [u8; 303] = hex_literal::hex!("0200000000010293cf02dd919c889519ee6ed3f5331eedeef581efdf907f256b3fa193178e575b0000000000fdffffff826492b5a975f732b60a59e2e8edc5397ce584c62af3b90dee755ba6ddef44d90000000000fdffffff032036963b0000000017a914f69543fb49aad08ce76bab6cc3b046792142289a876c0a06000000000017a914027806c946952bb0233ef92fc5b199c173e39aed870000000000000000036a0102014170a2b77c9c773c26033fdb1315238462c0d2b74d88b48a81e4d9b9d834a4dadd0547e8cb73e3bd774ca11a7ae4f7d59a498b2d0c7fdec45a9c13864de1c309f483014033d561c6f8ef430eafd0f7923312e81351212f5350193d9521c4c6b6c814336935565160f5790708389dc9395f1f833eb5a6d56b39debda9830a239dafa657b400000000");
const PAYOUT_TX_INDEX: u32 = 51;
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let winternitz_id: [u32; 8] = compute_image_id(BRIDGE_CIRCUIT_ELF).unwrap().into();
    let work_only_id: [u32; 8] = compute_image_id(WORK_ONLY_ELF).unwrap().into();

    println!("WINTERNITZ_ID: {:?}", winternitz_id);
    println!("WORK_ONLY_ID: {:?}", work_only_id);
    let headerchain_proof: Receipt = Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap();
    let headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();
    let mut mmr_native = MMRNative::new();
    for i in 0..=L1_BLOCK_HEIGHT {
        mmr_native.append(headers[i as usize].compute_block_hash());
    }

    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(&headerchain_proof.journal.bytes[..]).unwrap();

    let work_only_circuit_input: WorkOnlyCircuitInput = WorkOnlyCircuitInput {
        header_chain_circuit_output: block_header_circuit_output.clone(),
    };
    let work_only_groth16_proof_receipt: Receipt =
        call_work_only(headerchain_proof, &work_only_circuit_input);

    let g16_proof_receipt: &risc0_zkvm::Groth16Receipt<risc0_zkvm::ReceiptClaim> =
        work_only_groth16_proof_receipt.inner.groth16().unwrap();
    println!("G16 PROOF RECEIPT: {:?}", g16_proof_receipt);

    let seal =
        CircuitGroth16Proof::from_seal(g16_proof_receipt.seal.as_slice().try_into().unwrap());

    let compressed_proof = seal.to_compressed().unwrap();

    let commited_total_work: [u8; 16] = work_only_groth16_proof_receipt
        .journal
        .bytes
        .try_into()
        .unwrap();

    let mut compressed_proof_and_total_work: Vec<u8> = vec![0; 144];
    compressed_proof_and_total_work[0..128].copy_from_slice(&compressed_proof);
    compressed_proof_and_total_work[128..144].copy_from_slice(&commited_total_work);

    let n0 = compressed_proof_and_total_work.len();
    let log_d = 8;
    let params = Parameters::new(n0.try_into().unwrap(), log_d);
    let input: u64 = 1;
    let mut rng = SmallRng::seed_from_u64(input);
    let secret_key: Vec<u8> = (0..n0).map(|_| rng.gen()).collect();
    let pub_key: Vec<[u8; 20]> = generate_public_key(&params, &secret_key);
    let signature = sign_digits(&params, &secret_key, &compressed_proof_and_total_work);

    let (light_client_proof, lcp_receipt) =
        fetch_light_client_proof(L1_BLOCK_HEIGHT).await.unwrap();

    // Check if L2 height is correct ??
    let storage_proof = fetch_storage_proof(&light_client_proof.l2_height).await;
    let block_vec = TESTNET_BLOCK_47029.to_vec();
    let block_47029 = bitcoin::block::Block::consensus_decode(&mut block_vec.as_slice()).unwrap();
    let payout_tx =
        bitcoin::transaction::Transaction::consensus_decode(&mut PAYOUT_TX.as_ref()).unwrap();

    let block_47029_txids: Vec<[u8; 32]> = block_47029
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
        .collect();
    let mmr_inclusion_proof = mmr_native.generate_proof(72041);
    let block_47029_mt = BitcoinMerkleTree::new(block_47029_txids);
    let payout_tx_proof = block_47029_mt.generate_proof(PAYOUT_TX_INDEX);

    let spv: SPV = SPV {
        transaction: payout_tx.into(),
        block_inclusion_proof: payout_tx_proof,
        block_header: block_47029.header.into(),
        mmr_inclusion_proof: mmr_inclusion_proof.1,
    };

    let winternitz_details = WinternitzHandler {
        pub_key,
        params,
        signature: Some(signature),
        message: Some(compressed_proof_and_total_work),
    };

    let winternitz_circuit_input: WinternitzCircuitInput = WinternitzCircuitInput {
        winternitz_details: vec![winternitz_details],
        hcp: block_header_circuit_output,
        payout_spv: spv,
        lcp: light_client_proof,
        operator_id: 1,
        sp: storage_proof,
        num_watchtowers: 1,
    };

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&winternitz_circuit_input).unwrap());
    // let env = env.add_assumption(lcp_receipt).build().unwrap();
    let env = env.build().unwrap();
    let prover = default_prover();

    println!("PROVING WINTERNITZ CIRCUIT");
    let receipt = prover
        .prove_with_opts(env, BRIDGE_CIRCUIT_ELF, &ProverOpts::succinct())
        .unwrap()
        .receipt;
    println!("RECEIPT: {:?}", receipt);
    let receipt_bytes = borsh::to_vec(&receipt).unwrap();
    fs::write("proof.bin", &receipt_bytes).expect("Failed to write receipt to output file");
}

fn call_work_only(receipt: Receipt, input: &WorkOnlyCircuitInput) -> Receipt {
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
