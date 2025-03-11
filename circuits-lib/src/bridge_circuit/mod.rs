pub mod constants;
pub mod groth16;
pub mod groth16_verifier;
pub mod lc_proof;
pub mod storage_proof;
pub mod structs;
pub mod winternitz;

use crate::common::zkvm::ZkvmGuest;
use bitcoin::{hashes::Hash, TxOut};
use groth16::CircuitGroth16Proof;
use groth16_verifier::CircuitGroth16WithTotalWork;
use lc_proof::lc_proof_verifier;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use storage_proof::verify_storage_proofs;
use structs::BridgeCircuitInput;
use winternitz::{verify_winternitz_signature, WinternitzHandler};

pub const HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2421631365, 3264974484, 821027839, 1335612179, 1295879179, 713845602, 1229060261, 258954137,
];

/// TODO: Change this to a feature in the future
pub const IS_TEST: bool = {
    match option_env!("BRIDGE_CIRCUIT_MODE") {
        Some(mode) if matches!(mode.as_bytes(), b"test") => true,
        Some(mode) if matches!(mode.as_bytes(), b"prod") => false,
        None => false,
        _ => panic!("Invalid bridge circuit mode"),
    }
};

pub fn bridge_circuit(guest: &impl ZkvmGuest, work_only_image_id: [u8; 32]) {
    let input: BridgeCircuitInput = guest.read_from_host();
    assert_eq!(HEADER_CHAIN_METHOD_ID, input.hcp.method_id);

    // Verify the HCP
    guest.verify(input.hcp.method_id, &input.hcp);

    let (total_work, challenge_sending_watchtowers) = total_work_and_watchtower_flags(
        &input.winternitz_details,
        input.num_watchtowers,
        &work_only_image_id,
    );

    // If total work is less than the max total work of watchtowers, panic
    if input.hcp.chain_state.total_work < total_work {
        panic!(
            "Invalid total work: Total Work {:?} - Max Total Work: {:?}",
            input.hcp.chain_state.total_work, total_work
        );
    }

    // MMR WILL BE FETCHED FROM LC PROOF WHEN IT IS READY - THIS IS JUST FOR PROOF OF CONCEPT
    let mmr = input.hcp.chain_state.block_hashes_mmr;

    if !input.payout_spv.verify(mmr) {
        panic!("Invalid SPV proof");
    }

    // Light client proof verification
    let state_root = lc_proof_verifier(input.lcp.clone());

    // Storage proof verification for deposit tx index and withdrawal outpoint
    let user_wd_outpoint_str = verify_storage_proofs(&input.sp, state_root);

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

    let last_output = input.payout_spv.transaction.output.last().unwrap();

    let deposit_constant =
        deposit_constant(last_output, &input.winternitz_details, input.sp.txid_hex);

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
}

fn convert_to_groth16_and_verify(message: &[u8], pre_state: &[u8; 32]) -> bool {
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
    groth16_proof.verify(pre_state)
}

pub fn total_work_and_watchtower_flags(
    winternitz_details: &[WinternitzHandler],
    num_watchtowers: u32,
    work_only_image_id: &[u8; 32],
) -> ([u8; 32], [u8; 20]) {
    let mut wt_messages_with_idxs: Vec<(usize, Vec<u8>)> = vec![];
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];

    assert_eq!(
        winternitz_details.len(),
        num_watchtowers as usize,
        "Invalid number of watchtowers"
    );

    // Verify Winternitz signatures
    for (wt_idx, winternitz_handler) in winternitz_details.iter().enumerate() {
        if let (Some(_signature), Some(message)) =
            (&winternitz_handler.signature, &winternitz_handler.message)
        {
            if IS_TEST || verify_winternitz_signature(winternitz_handler) {
                challenge_sending_watchtowers[wt_idx / 8] |= 1 << (wt_idx % 8);
                wt_messages_with_idxs.push((wt_idx, message.clone()));
            }
        }
    }

    // sort by total work from the largest to the smallest
    wt_messages_with_idxs.sort_by(|a, b| b.1.cmp(&a.1));
    let mut total_work = [0u8; 32];

    // More elegant way to do this? (if let + find?)
    for pair in wt_messages_with_idxs.iter() {
        // Grooth16 verification of work only circuit
        if IS_TEST || convert_to_groth16_and_verify(&pair.1, work_only_image_id) {
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

    (total_work, challenge_sending_watchtowers)
}

fn deposit_constant(
    last_output: &TxOut,
    winternitz_details: &[WinternitzHandler],
    move_txid_hex: [u8; 32],
) -> [u8; 32] {
    let last_output_script = last_output.script_pubkey.to_bytes();

    // OP_RETURN check
    assert!(last_output_script[0] == 0x6a);

    let len: usize = last_output_script[1] as usize;

    if len > 32 {
        panic!("Invalid operator id length");
    }

    let mut operator_id = [0u8; 32];
    operator_id[..len].copy_from_slice(&last_output_script[2..2 + len]);

    let num_wts = winternitz_details.len();
    let pk_size = winternitz_details[0].pub_key.len();
    let mut pub_key_concat: Vec<u8> = vec![0; num_wts * pk_size * 20];
    for (i, wots_handler) in winternitz_details.iter().enumerate() {
        for (j, pubkey) in wots_handler.pub_key.iter().enumerate() {
            pub_key_concat[(pk_size * i * 20 + j * 20)..(pk_size * i * 20 + (j + 1) * 20)]
                .copy_from_slice(pubkey);
        }
    }

    let wintertniz_pubkeys_digest: [u8; 32] = Sha256::digest(&pub_key_concat).into();
    let pre_deposit_constant = [move_txid_hex, wintertniz_pubkeys_digest, operator_id].concat();

    Sha256::digest(&pre_deposit_constant).into()
}
