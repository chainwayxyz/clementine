use alloy_rpc_client::ClientBuilder;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Transaction;
use borsh::{self, BorshDeserialize};
use bridge_circuit_host::config::PARAMETERS;
use bridge_circuit_host::{fetch_light_client_proof, fetch_storage_proof};
use circuits_lib::bridge_circuit_core::groth16::CircuitGroth16Proof;
use circuits_lib::bridge_circuit_core::structs::{BridgeCircuitInput, WorkOnlyCircuitInput};
use circuits_lib::bridge_circuit_core::winternitz::{
    generate_public_key, sign_digits, Parameters, WinternitzHandler,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use risc0_to_bitvm2_core::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
use risc0_to_bitvm2_core::merkle_tree::BitcoinMerkleTree;
use risc0_to_bitvm2_core::mmr_native::MMRNative;
use risc0_to_bitvm2_core::spv::SPV;
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::convert::TryInto;
use std::fs;
use structs::BridgeCircuitHostParams;
pub mod structs;

const LIGHT_CLIENT_PROVER_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz/";

const HEADERS: &[u8] = include_bytes!("bin-files/testnet4_headers.bin");
const TESTNET_BLOCK_72041: &[u8] = include_bytes!("bin-files/testnet4_block_72041.bin");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest");
const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("bin-files/testnet4_first_72075.bin");
const PAYOUT_TX: &[u8; 303] = include_bytes!("bin-files/payout_tx.bin");
const BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-bridge-circuit-guest");

#[tokio::main]
async fn main() {
    let citrea_rpc_client = ClientBuilder::default().http(CITREA_TESTNET_RPC.parse().unwrap());
    let light_client_rpc_client =
        ClientBuilder::default().http(LIGHT_CLIENT_PROVER_URL.parse().unwrap());
    let headerchain_proof: Receipt = Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap();
    let spv = create_spv().await;
    let bridge_circuit_host_params = BridgeCircuitHostParams {
        light_client_rpc_client,
        citrea_rpc_client,
        headerchain_proof,
        spv,
    };
    prove_bridge_circuit(bridge_circuit_host_params).await;
}

async fn prove_bridge_circuit(bridge_circuit_host_params: BridgeCircuitHostParams) {
    let winternitz_id: [u32; 8] = compute_image_id(BRIDGE_CIRCUIT_ELF).unwrap().into();
    let work_only_id: [u32; 8] = compute_image_id(WORK_ONLY_ELF).unwrap().into();

    println!("WINTERNITZ_ID: {:?}", winternitz_id);
    println!("WORK_ONLY_ID: {:?}", work_only_id);

    let block_header_circuit_output: BlockHeaderCircuitOutput =
        borsh::BorshDeserialize::try_from_slice(
            &bridge_circuit_host_params.headerchain_proof.journal.bytes[..],
        )
        .unwrap();

    let work_only_circuit_input: WorkOnlyCircuitInput = WorkOnlyCircuitInput {
        header_chain_circuit_output: block_header_circuit_output.clone(),
    };
    let work_only_groth16_proof_receipt: Receipt = call_work_only(
        bridge_circuit_host_params.headerchain_proof,
        &work_only_circuit_input,
    );

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

    let (light_client_proof, _lcp_receipt) =
        fetch_light_client_proof(72471, bridge_circuit_host_params.light_client_rpc_client)
            .await
            .unwrap();

    // Check if L2 height is correct ??
    let storage_proof = fetch_storage_proof(
        &light_client_proof.l2_height,
        bridge_circuit_host_params.citrea_rpc_client,
    )
    .await;

    let winternitz_details = WinternitzHandler {
        pub_key,
        params,
        signature: Some(signature),
        message: Some(compressed_proof_and_total_work),
    };

    let winternitz_circuit_input: BridgeCircuitInput = BridgeCircuitInput {
        winternitz_details: vec![winternitz_details],
        hcp: block_header_circuit_output,
        payout_spv: bridge_circuit_host_params.spv,
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

async fn create_spv() -> SPV {
    let payout_tx = Transaction::consensus_decode(&mut PAYOUT_TX.as_ref()).unwrap();
    let headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();
    let mut mmr_native = MMRNative::new();
    for i in 0..=PARAMETERS.l1_block_height {
        mmr_native.append(headers[i as usize].compute_block_hash());
    }
    let block_vec = TESTNET_BLOCK_72041.to_vec();
    let block_72041 = bitcoin::block::Block::consensus_decode(&mut block_vec.as_slice()).unwrap();

    let block_72041_txids: Vec<[u8; 32]> = block_72041
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
        .collect();
    let mmr_inclusion_proof = mmr_native.generate_proof(PARAMETERS.payment_block_height);
    let block_72041_mt = BitcoinMerkleTree::new(block_72041_txids);
    let payout_tx_proof = block_72041_mt.generate_proof(PARAMETERS.payout_tx_index);

    SPV {
        transaction: payout_tx.into(),
        block_inclusion_proof: payout_tx_proof,
        block_header: block_72041.header.into(),
        mmr_inclusion_proof: mmr_inclusion_proof.1,
    }
}
