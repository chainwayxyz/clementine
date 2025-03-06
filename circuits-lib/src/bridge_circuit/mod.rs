pub mod constants;
pub mod groth16;
pub mod lc_proof;
pub mod storage_proof;

use crate::bridge_circuit::groth16::CircuitGroth16WithTotalWork;
use crate::bridge_circuit_core;
use crate::common::zkvm::ZkvmGuest;
use bitcoin::hashes::Hash;
use bridge_circuit_core::groth16::CircuitGroth16Proof;
use bridge_circuit_core::structs::BridgeCircuitInput;
use bridge_circuit_core::winternitz::{verify_winternitz_signature, WinternitzHandler};
use lc_proof::lc_proof_verifier;
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use storage_proof::verify_storage_proofs;

pub fn verify_winternitz_and_groth16(input: &WinternitzHandler) -> bool {
    let start = env::cycle_count();
    let res = verify_winternitz_signature(input);
    let end = env::cycle_count();
    println!("WNV: {}", end - start);
    res
}

pub fn convert_to_groth16_and_verify(message: &[u8], pre_state: &[u8; 32]) -> bool {
    let compressed_seal: [u8; 128] = match message[0..128].try_into() {
        Ok(compressed_seal) => compressed_seal,
        Err(_) => return false,
    };

    let total_work: [u8; 16] = match message[128..144].try_into() {
        Ok(total_work) => total_work,
        Err(_) => return false,
    };
    println!("Total work: {:?}", total_work);

    let seal = match CircuitGroth16Proof::from_compressed(&compressed_seal) {
        Ok(seal) => seal,
        Err(_) => return false,
    };

    let groth16_proof = CircuitGroth16WithTotalWork::new(seal, total_work);
    let start = env::cycle_count();
    let res = groth16_proof.verify(pre_state);
    let end = env::cycle_count();
    println!("G16V: {}", end - start);
    println!("{}", res);
    res
}

pub fn bridge_circuit(guest: &impl ZkvmGuest, work_only_image_id: [u8; 32]) {
    let start = env::cycle_count();
    let input: BridgeCircuitInput = guest.read_from_host();

    let mut watchtower_flags: Vec<bool> = vec![];
    let mut wt_messages_with_idxs: Vec<(usize, Vec<u8>)> = vec![];

    if input.winternitz_details.len() != input.num_watchtowers as usize {
        panic!("Invalid number of watchtowers");
    }

    // Verify Winternitz signatures
    for (wt_idx, winternitz_handler) in input.winternitz_details.iter().enumerate() {
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

    // sort by total work from the largest to the smallest
    wt_messages_with_idxs.sort_by(|a, b| b.1.cmp(&a.1));
    let mut total_work = [0u8; 32];
    for pair in wt_messages_with_idxs.iter() {
        // Grooth16 verification of work only circuit
        if convert_to_groth16_and_verify(&pair.1, &work_only_image_id) {
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

    // If total work is less than the max total work of watchtowers, panic
    if input.hcp.chain_state.total_work < total_work {
        panic!(
            "Invalid total work: Total Work {:?} - Max Total Work: {:?}",
            input.hcp.chain_state.total_work, total_work
        );
    }

    let num_wts = input.winternitz_details.len();
    let pk_size = input.winternitz_details[0].pub_key.len();
    let mut pub_key_concat: Vec<u8> = vec![0; num_wts * pk_size * 20];
    for (i, wots_handler) in input.winternitz_details.iter().enumerate() {
        for (j, pubkey) in wots_handler.pub_key.iter().enumerate() {
            pub_key_concat[(pk_size * i * 20 + j * 20)..(pk_size * i * 20 + (j + 1) * 20)]
                .copy_from_slice(pubkey);
        }
    }

    // MMR WILL BE FETCHED FROM LC PROOF WHEN IT IS READY - THIS IS JUST FOR PROOF OF CONCEPT
    let mmr = input.hcp.chain_state.block_hashes_mmr;

    // SPV verification of payout transaction
    println!("SPV verification {:?}", input.payout_spv.verify(mmr));

    // Light client proof verification
    let state_root = lc_proof_verifier(input.lcp.clone());

    // Storage proof verification for deposit tx index and withdrawal outpoint
    let user_wd_outpoint_str = verify_storage_proofs(&input.sp, state_root);

    println!("User withdrawal outpoint: {:?}", user_wd_outpoint_str);

    let user_wd_outpoint = num_bigint::BigUint::from_str(&user_wd_outpoint_str).unwrap();
    let user_wd_txid = bitcoin::Txid::from_byte_array(
        user_wd_outpoint
            .to_bytes_be()
            .as_slice()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        user_wd_txid,
        input.payout_spv.transaction.input[0].previous_output.txid
    );
    println!(
        "Payout transaction output: {:?}",
        input.payout_spv.transaction.output
    );

    let last_output = input.payout_spv.transaction.output.last().unwrap();
    let last_output_script = last_output.script_pubkey.to_bytes();

    assert!(last_output_script[0] == 0x6a);
    let len: u8 = last_output_script[1];
    let mut operator_id: [u8; 32] = [0u8; 32];
    if len > 32 {
        panic!("Invalid operator id length");
    } else {
        operator_id[..len as usize].copy_from_slice(&last_output_script[2..(2 + len) as usize]);
    }
    println!("Operator ID: {:?}", operator_id);

    let wintertniz_pubkeys_digest: [u8; 32] = Sha256::digest(&pub_key_concat).into();
    let pre_deposit_constant = [input.sp.txid_hex, wintertniz_pubkeys_digest, operator_id].concat();

    let deposit_constant: [u8; 32] = Sha256::digest(&pre_deposit_constant).into();
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];
    // Convert bools to bit flags
    for (i, &flag) in watchtower_flags.iter().enumerate() {
        if flag {
            challenge_sending_watchtowers[i / 8] |= 1 << (i % 8);
        }
    }

    let latest_blockhash: [u8; 20] = input.hcp.chain_state.best_block_hash[12..32]
        .try_into()
        .unwrap();
    let payout_tx_blockhash: [u8; 20] = input.payout_spv.block_header.compute_block_hash()[12..32]
        .try_into()
        .unwrap();

    let concatenated_data = [
        payout_tx_blockhash,
        latest_blockhash,
        challenge_sending_watchtowers,
    ]
    .concat();
    let binding = blake3::hash(&concatenated_data);
    let hash_bytes = binding.as_bytes();

    let concat_journal = [deposit_constant, *hash_bytes].concat();
    let journal_hash = blake3::hash(&concat_journal);

    guest.commit(journal_hash.as_bytes());
    let end = env::cycle_count();
    println!("WNT: {}", end - start);
}
