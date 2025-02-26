use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use borsh::{self, BorshDeserialize};
use final_spv::merkle_tree::BitcoinMerkleTree;
use final_spv::spv::SPV;
use header_chain::header_chain::{
    BlockHeaderCircuitOutput, CircuitBlockHeader};
use header_chain::mmr_native::MMRNative;
use host::{fetch_light_client_proof, fetch_storage_proof};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt,
};
use std::convert::TryInto;
use bridge_circuit_core::groth16::CircuitGroth16Proof;
use bridge_circuit_core::winternitz::{
    generate_public_key, sign_digits, Parameters, WinternitzCircuitInput, WinternitzHandler,
};
use bridge_circuit_core::WorkOnlyCircuitInput;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{layer::SubscriberExt, filter::EnvFilter};
const HEADERS: &[u8] = include_bytes!("bin-files/testnet4-headers.bin");
const TESTNET_BLOCK_47029: &[u8] = include_bytes!("bin-files/testnet4_block_47029.bin");
const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("bin-files/first_9.bin");
const BRIDGE_CIRCUIT_ELF: &[u8] = include_bytes!("../../../risc0-circuits/elfs/testnet4-bridge-circuit-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../../risc0-circuits/elfs/testnet4-work-only-guest");

const PAYOUT_TX: [u8; 301] = hex_literal::hex!("02000000000102d43afcd7236286bee4eb5316c597b9977cae4ac69eb8f40d4a47155b94db64540000000000fdffffffeb0577a0d00e1774686e4ef6107d85509a83b63f63056a87ee4a9ff551846bf20100000000fdffffff032036963b00000000160014b9d8ffd3b02047bc33442a2c427abc54ba53a6f83a906b1e020000001600142551d4ad0ab54037f8770ae535ce2e3e56e3f9d50000000000000000036a010101418c1976233f4523d6c988d6c9430b292d5cac77d2358117eeb7dc4dfab728da305ed183fdd44054d368398b64de7ed057fe28c31c689d8ca8c9ea813e100f9203830140b452bea0f0b6ca19442142034d3d9fedfa10bec5e58c12f1f407905214a8c8594f906cb67ffac173fedfcabff55c09e2d44cb9b2cd48f87deae15f729283bf2900000000");

#[tokio::main]
async fn main() {

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
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
    for header in headers.iter() {
        mmr_native.append(header.compute_block_hash());
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


    let l1_hegith = 70029;
    let (light_client_proof, lcp_receipt) = fetch_light_client_proof(l1_hegith).await.unwrap();

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
    let mmr_inclusion_proof = mmr_native.generate_proof(47029);
    let block_47029_mt = BitcoinMerkleTree::new(block_47029_txids);
    let payout_tx_proof = block_47029_mt.generate_proof(15); // 16th tx
    
    let spv: SPV = SPV {
        transaction: payout_tx.into(),
        block_inclusion_proof: payout_tx_proof,
        block_header: block_47029.header.into(),
        mmr_inclusion_proof: mmr_inclusion_proof.1,
    };

    let winternitz_details = WinternitzHandler {
        pub_key,
        params,
        signature,
        message: compressed_proof_and_total_work,
    };

    let winternitz_circuit_input: WinternitzCircuitInput = WinternitzCircuitInput {
        winternitz_details: vec![winternitz_details],
        hcp: block_header_circuit_output,
        payout_spv: spv,
        lcp: light_client_proof,
        operator_id: 1,
        sp : storage_proof,
    };

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&winternitz_circuit_input).unwrap());
    let env = env.add_assumption(lcp_receipt).build().unwrap();
    let executor = default_executor();

    let _ = executor.execute(env, BRIDGE_CIRCUIT_ELF);
}

fn call_work_only(receipt: Receipt, input: &WorkOnlyCircuitInput) -> Receipt {
    let mut binding = ExecutorEnv::builder();
    binding.add_assumption(receipt);
    let env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    let env = env.build().unwrap();
    let prover = default_prover();
    println!("input: {:?}", input);
    prover
        .prove_with_opts(env, WORK_ONLY_ELF, &ProverOpts::groth16())
        .unwrap()
        .receipt
}
