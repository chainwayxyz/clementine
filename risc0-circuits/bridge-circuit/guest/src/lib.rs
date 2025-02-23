use bitcoin::hashes::Hash;
use groth16::CircuitGroth16WithTotalWork;
use storage_proof::verify_storage_proofs;
use lc_proof::lc_proof_verifier;
use risc0_zkvm::guest::env;
use std::str::FromStr;
use bridge_circuit_core::utils::hash160;
use bridge_circuit_core::winternitz::{
    verify_winternitz_signature, WinternitzCircuitInput, WinternitzCircuitOutput, WinternitzHandler
};
use bridge_circuit_core::zkvm::ZkvmGuest;
use bridge_circuit_core::groth16::CircuitGroth16Proof;
mod constants;
mod lc_proof;
mod storage_proof;
mod groth16;

pub fn verify_winternitz_and_groth16(input: &WinternitzHandler) -> bool {
    let start = env::cycle_count();
    let res = verify_winternitz_signature(input);
    let end = env::cycle_count();
    println!("WNV: {}", end - start);
    res
}

pub fn convert_to_groth16_and_verify(message: &Vec<u8>) -> bool {
    let compressed_seal: [u8; 128] = match message[0..128].try_into() {
        Ok(compressed_seal) => compressed_seal,
        Err(_) => return false,
    };
    
    let total_work: [u8; 16] = match message[128..144].try_into() {
        Ok(total_work) => total_work,
        Err(_) => return false,
    };

    let seal = match CircuitGroth16Proof::from_compressed(&compressed_seal) {
        Ok(seal) => seal,
        Err(_) => return false,
    };

    let groth16_proof = CircuitGroth16WithTotalWork::new(seal, total_work);
    let start = env::cycle_count();
    let res = groth16_proof.verify();
    let end = env::cycle_count();
    println!("G16V: {}", end - start);
    println!("{}", res);
    res
}

pub fn winternitz_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: WinternitzCircuitInput = guest.read_from_host();

    let mut watchtower_flags: Vec<bool> = vec![];
    let mut wt_messages_with_idxs: Vec<(usize, Vec<u8>)> = vec![];

    // Verify Winternitz signatures
    for (wt_idx, winternitz_handler) in input.winternitz_details.iter().enumerate() {
        let flag = verify_winternitz_signature(winternitz_handler);
        watchtower_flags.push(flag);
        
        if flag {
            wt_messages_with_idxs.push((wt_idx, winternitz_handler.message.clone()));
        }
    }

    // sort by total work from the largest to the smallest
    wt_messages_with_idxs.sort_by(|a, b| b.1.cmp(&a.1));
    let mut total_work = [0u8; 32];
    for pair in wt_messages_with_idxs.iter() {

        // Grooth16 verification of work only circuit
        if convert_to_groth16_and_verify(&pair.1) {
            total_work[16..32].copy_from_slice(&pair.1[128..144].chunks_exact(4).flat_map(|c| c.iter().rev()).copied().collect::<Vec<_>>());
            break;
        }
    }

    // If total work is less than the max total work of watchtowers, panic
    if input.hcp.chain_state.total_work < total_work {
        panic!("Invalid total work: Total Work {:?} - Max Total Work: {:?}", input.hcp.chain_state.total_work, total_work);
    }

    let num_wts = input.winternitz_details.len();
    let pk_size = input.winternitz_details[0].pub_key.len();
    let mut pub_key_concat: Vec<u8> = vec![0; num_wts * pk_size * 20];
    for (i, wots_handler) in input.winternitz_details.iter().enumerate() {
        for (j, pubkey) in wots_handler.pub_key.iter().enumerate() {
            pub_key_concat[(pk_size * i * 20 + j * 20)..(pk_size * i * 20 + (j + 1) * 20)].copy_from_slice(pubkey);
        }
    }

    // MMR WILL BE FETCHED FROM LC PROOF WHEN IT IS READY - THIS IS JUST FOR PROOF OF CONCEPT
    let mmr = input.hcp.chain_state.block_hashes_mmr;

    // SPV verification of payout transaction
    println!("SPV verification {:?}", input.payout_spv.verify(mmr));

    // Light client proof verification
    let state_root = lc_proof_verifier(input.lcp.clone());

    // Storage proof verification for deposit tx index and withdrawal outpoint
    let user_wd_outpoint_str= verify_storage_proofs(&input.sp, state_root);

    let user_wd_outpoint = num_bigint::BigUint::from_str(&user_wd_outpoint_str).unwrap();
    let user_wd_txid = bitcoin::Txid::from_byte_array(user_wd_outpoint.to_bytes_be().as_slice().try_into().unwrap());
    assert_eq!(user_wd_txid, input.payout_spv.transaction.input[0].previous_output.txid);
    println!("Payout transaction output: {:?}", input.payout_spv.transaction.output);

    let last_output = input.payout_spv.transaction.output.last().unwrap();
    let last_output_script = last_output.script_pubkey.to_bytes();

    assert!(last_output_script[0] == 0x6a);
    let len = last_output_script[1];
    let operator_id  = last_output_script[2..(2 + len as usize)].to_vec();

    guest.commit(&WinternitzCircuitOutput {
        winternitz_pubkeys_digest: hash160(&pub_key_concat),
        correct_watchtowers: watchtower_flags,
        payout_tx_blockhash: input.payout_spv.block_header.compute_block_hash(),
        last_blockhash: [0u8; 32], // TODO: Change here - WE'LL CHANGE WHEN WITHDRAWAL IS AVAILABLE
        deposit_txid: input.sp.txid_hex,
        operator_id: operator_id,
    });
    let end = env::cycle_count();
    println!("WNT: {}", end - start);
}
