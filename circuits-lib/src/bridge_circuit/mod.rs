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
/// Executes the bridge circuit in a zkVM environment, verifying multiple cryptographic proofs
/// related to watchtower work, SPV, and storage proofs.
///
/// # Parameters
///
/// - `guest`: A reference to a zkVM guest implementing `ZkvmGuest`.
/// - `work_only_image_id`: A 32-byte array representing the work-only image ID used in verification.
///
/// # Functionality
///
/// 1. Reads the `BridgeCircuitInput` from the host.
/// 2. Ensures the method ID in `hcp` (header chain proof) matches `HEADER_CHAIN_METHOD_ID`.
/// 3. Verifies the header chain proof (`hcp`).
/// 4. Computes total work and watchtower challenge flags using `total_work_and_watchtower_flags`.
/// 5. Validates that the computed `total_work` does not exceed the total work in `hcp.chain_state`.
/// 6. Fetches the MMR (Merkle Mountain Range) for block hashes from `hcp.chain_state`.
/// 7. Verifies the SPV proof (`payout_spv`) using the fetched MMR.
/// 8. Verifies the light client proof using `lc_proof_verifier`.
/// 9. Checks storage proofs for deposit and withdrawal transaction indices using `verify_storage_proofs`.
/// 10. Converts the verified withdrawal outpoint into a Bitcoin transaction ID.
/// 11. Ensures the withdrawal transaction ID matches the input reference in `payout_spv.transaction`.
/// 12. Computes the `deposit_constant` using the last output of the payout transaction.
/// 13. Extracts and truncates the latest block hash and the payout transaction’s block hash.
/// 14. Computes a Blake3 hash over concatenated block hash and watchtower flags.
/// 15. Generates a final journal hash using Blake3 over concatenated data and commits it.
///
/// # Panics
///
/// - If the method ID in `hcp` does not match `HEADER_CHAIN_METHOD_ID`.
/// - If `max_total_work` given by watchtowers is greater than `hcp.chain_state.total_work`.
/// - If the SPV proof is invalid.
/// - If the storage proof verification fails.
/// - If the withdrawal transaction ID does not match the referenced input in `payout_spv`.
pub fn bridge_circuit(guest: &impl ZkvmGuest, work_only_image_id: [u8; 32]) {
    let input: BridgeCircuitInput = guest.read_from_host();
    assert_eq!(HEADER_CHAIN_METHOD_ID, input.hcp.method_id);

    // Verify the HCP
    guest.verify(input.hcp.method_id, &input.hcp);

    let (max_total_work, challenge_sending_watchtowers) = total_work_and_watchtower_flags(
        &input.winternitz_details,
        input.num_watchtowers,
        &work_only_image_id,
    );

    // If total work is less than the max total work of watchtowers, panic
    if input.hcp.chain_state.total_work < max_total_work {
        panic!(
            "Invalid total work: Total Work {:?} - Max Total Work: {:?}",
            input.hcp.chain_state.total_work, max_total_work
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
        user_wd_txid, input.payout_spv.transaction.input[0].previous_output.txid,
        "Invalid withdrawal transaction ID"
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

/// Converts a message into a Groth16 proof structure and verifies it against a given pre-state. (only for work-only circuit)
///
/// # Parameters
///
/// - `message`: A byte slice containing the proof data.
/// - `pre_state`: A 32-byte array representing the initial state for verification.
///
/// # Returns
///
/// - `true` if the Groth16 proof is successfully verified.
/// - `false` if any step in the process fails (e.g., invalid message length, failed deserialization, or failed proof verification).
///
/// # Failure Cases
///
/// - If the message is shorter than `144` bytes, the function returns `false`.
/// - If deserialization of the compressed seal fails, it returns `false`.
/// - If Groth16 proof verification fails, it returns `false`.
fn convert_to_groth16_and_verify(message: &[u8], image_id: &[u8; 32]) -> bool {
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
    groth16_proof.verify(image_id)
}

/// Computes the total work and watchtower challenge flags based on Winternitz signatures.
///
/// # Parameters
///
/// - `winternitz_details`: A slice of `WinternitzHandler`, each containing a signature and a message.
/// - `num_watchtowers`: The expected number of watchtowers (must match `winternitz_details.len()`, otherwise the function panics).
/// - `work_only_image_id`: A 32-byte array used for Groth16 verification of the work-only circuit.
///
/// # Returns
///
/// A tuple containing:
/// - `[u8; 32]`: A 32-byte array representing the total work.
/// - `[u8; 20]`: A 20-byte array representing the watchtower challenge flags.
///
/// # Panics
///
/// - If `winternitz_details.len()` does not match `num_watchtowers`.
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

/// Computes a deposit constant hash using transaction output data, Winternitz public keys, and a move transaction ID.
///
/// # Parameters
///
/// - `last_output`: A reference to the last transaction output (`TxOut`).
/// - `winternitz_details`: A slice of `WinternitzHandler`, containing public keys.
/// - `move_txid_hex`: A 32-byte array representing the move transaction ID.
///
/// # Returns
///
/// A 32-byte array (`[u8; 32]`) representing the SHA-256 hash of the concatenated input components.
///
/// # Panics
///
/// - If the `script_pubkey` of `last_output` does not start with `OP_RETURN` (`0x6a`).
/// - If the length of the operator ID (extracted from `script_pubkey`) exceeds 32 bytes.
fn deposit_constant(
    last_output: &TxOut,
    winternitz_details: &[WinternitzHandler],
    move_txid_hex: [u8; 32],
) -> [u8; 32] {
    let last_output_script = last_output.script_pubkey.to_bytes();

    // OP_RETURN check
    assert!(last_output_script[0] == 0x6a);

    if last_output_script.len() < 3 {
        panic!("OP_RETURN script too short");
    }

    let len: usize = last_output_script[1] as usize;

    if len > 32 {
        panic!("Invalid operator id length");
    }

    let mut operator_id = [0u8; 32];
    operator_id[..len].copy_from_slice(&last_output_script[2..2 + len]);

    let pub_key_concat: Vec<u8> = winternitz_details
        .iter()
        .flat_map(|wots_handler| wots_handler.pub_key.iter().flatten())
        .copied()
        .collect();

    let wintertniz_pubkeys_digest: [u8; 32] = Sha256::digest(&pub_key_concat).into();
    let pre_deposit_constant = [move_txid_hex, wintertniz_pubkeys_digest, operator_id].concat();

    Sha256::digest(&pre_deposit_constant).into()
}

#[cfg(test)]
mod tests {
    use crate::bridge_circuit::winternitz::Parameters;

    use super::*;
    use bitcoin::{opcodes, script::Builder, Amount};

    #[test]
    fn test_deposit_constant() {
        let script_buf = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice([0x02])
            .into_script();
        let last_output = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: script_buf,
        };

        let winternitz_details = vec![WinternitzHandler {
            pub_key: vec![[
                147, 0, 0, 0, 162, 22, 250, 184, 250, 140, 238, 8, 88, 92, 50, 253, 80, 242, 185,
                70,
            ]],
            signature: None,
            message: None,
            params: Parameters::new(0, 8),
        }];

        let move_txid_hex: [u8; 32] = [
            187, 37, 16, 52, 104, 164, 103, 56, 46, 217, 245, 133, 18, 154, 212, 3, 49, 181, 68,
            37, 21, 93, 111, 15, 174, 140, 121, 147, 145, 238, 46, 127,
        ];

        let expected_deposit_constant: [u8; 32] = [
            95, 130, 146, 18, 194, 83, 141, 245, 190, 209, 190, 177, 204, 238, 255, 133, 118, 221,
            148, 4, 94, 1, 134, 27, 164, 67, 28, 164, 159, 202, 14, 180,
        ];

        let result = deposit_constant(&last_output, &winternitz_details, move_txid_hex);

        assert_eq!(
            result, expected_deposit_constant,
            "Deposit constant mismatch"
        );
    }

    #[test]
    #[should_panic]
    fn test_deposit_constant_failure_invalid_op_return() {
        let script_buf = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script();
        let last_output = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: script_buf,
        };

        let winternitz_details = vec![WinternitzHandler {
            pub_key: vec![[
                147, 0, 0, 0, 162, 22, 250, 184, 250, 140, 238, 8, 88, 92, 50, 253, 80, 242, 185,
                70,
            ]],
            signature: None,
            message: None,
            params: Parameters::new(0, 8),
        }];

        let move_txid_hex: [u8; 32] = [
            187, 37, 16, 52, 104, 164, 103, 56, 46, 217, 245, 133, 18, 154, 212, 3, 49, 181, 68,
            37, 21, 93, 111, 15, 174, 140, 121, 147, 145, 238, 46, 127,
        ];

        deposit_constant(&last_output, &winternitz_details, move_txid_hex);
    }
}
