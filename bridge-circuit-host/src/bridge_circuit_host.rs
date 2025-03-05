use crate::structs::BridgeCircuitHostParams;
use borsh;
use circuits_lib::bridge_circuit_core::structs::{BridgeCircuitInput, WorkOnlyCircuitInput};

use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

const BRIDGE_CIRCUIT_ELF: &[u8] =
    include_bytes!("../../risc0-circuits/elfs/testnet4-bridge-circuit-guest");
const WORK_ONLY_ELF: &[u8] = include_bytes!("../../risc0-circuits/elfs/testnet4-work-only-guest");

pub async fn prove_bridge_circuit(bridge_circuit_host_params: BridgeCircuitHostParams) -> Receipt {
    let bridge_circuit_input: BridgeCircuitInput = BridgeCircuitInput {
        winternitz_details: bridge_circuit_host_params.winternitz_details,
        hcp: bridge_circuit_host_params.block_header_circuit_output, // This will change in the future
        payout_spv: bridge_circuit_host_params.spv,
        lcp: bridge_circuit_host_params.light_client_proof,
        sp: bridge_circuit_host_params.storage_proof,
        num_watchtowers: 1,
    };

    let mut binding = ExecutorEnv::builder();
    let env = binding.write_slice(&borsh::to_vec(&bridge_circuit_input).unwrap());
    // let env = env.add_assumption(bridge_circuit_host_params.lcp_receipt).add_assumption(bridge_circuit_host_params.headerchain_receipt).build().unwrap();
    let env = env.build().unwrap();
    let prover = default_prover();

    tracing::info!("PROVING Bridge CIRCUIT");
    prover
        .prove_with_opts(env, BRIDGE_CIRCUIT_ELF, &ProverOpts::succinct())
        .unwrap()
        .receipt
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

#[cfg(test)]
mod tests {
    use crate::config::PARAMETERS;
    use crate::{fetch_light_client_proof, fetch_storage_proof};
    use alloy_rpc_client::ClientBuilder;
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash;
    use bitcoin::Transaction;
    use borsh::BorshDeserialize;
    use circuits_lib::bridge_circuit_core::groth16::CircuitGroth16Proof;
    use circuits_lib::bridge_circuit_core::structs::WorkOnlyCircuitInput;
    use final_spv::merkle_tree::BitcoinMerkleTree;
    use final_spv::spv::SPV;
    use header_chain::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
    use header_chain::mmr_native::MMRNative;
    use risc0_zkvm::Receipt;
    use std::convert::TryInto;

    use super::*;

    const LIGHT_CLIENT_PROVER_URL: &str = "https://light-client-prover.testnet.citrea.xyz/";
    const CITREA_TESTNET_RPC: &str = "https://rpc.testnet.citrea.xyz/";

    const HEADERS: &[u8] = include_bytes!("bin-files/testnet4_headers.bin");
    const HEADER_CHAIN_INNER_PROOF: &[u8] = include_bytes!("bin-files/testnet4_first_72075.bin");
    const PAYOUT_TX: &[u8; 303] = include_bytes!("bin-files/payout_tx.bin");
    const TESTNET_BLOCK_72041: &[u8] = include_bytes!("bin-files/testnet4_block_72041.bin");

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
        let block_72041 =
            bitcoin::block::Block::consensus_decode(&mut block_vec.as_slice()).unwrap();

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

    #[tokio::test]
    #[ignore = "This test will take an eternity. Only for debugging purposes."]
    async fn bridge_circuit_test() {
        let citrea_rpc_client = ClientBuilder::default().http(CITREA_TESTNET_RPC.parse().unwrap());
        let light_client_rpc_client =
            ClientBuilder::default().http(LIGHT_CLIENT_PROVER_URL.parse().unwrap());
        let headerchain_receipt: Receipt =
            Receipt::try_from_slice(HEADER_CHAIN_INNER_PROOF).unwrap();
        let spv = create_spv().await;

        let block_header_circuit_output: BlockHeaderCircuitOutput =
            borsh::BorshDeserialize::try_from_slice(&headerchain_receipt.journal.bytes[..])
                .unwrap();

        let work_only_circuit_input: WorkOnlyCircuitInput = WorkOnlyCircuitInput {
            header_chain_circuit_output: block_header_circuit_output.clone(),
        };

        println!("PROVING WORK ONLY CIRCUIT");
        let work_only_groth16_proof_receipt: Receipt =
            prove_work_only(headerchain_receipt.clone(), &work_only_circuit_input);

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

        let winternitz_details = generate_winternitz(&compressed_proof, &commited_total_work);

        let (light_client_proof, lcp_receipt) =
            fetch_light_client_proof(72471, light_client_rpc_client)
                .await
                .unwrap();

        let storage_proof =
            fetch_storage_proof(&light_client_proof.l2_height, citrea_rpc_client).await;

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
        println!("PROVING BRIDGE CIRCUIT");
        prove_bridge_circuit(bridge_circuit_host_params).await;
    }
}
