pub mod constants;
pub mod groth16;
pub mod groth16_verifier;
pub mod lc_proof;
pub mod storage_proof;
pub mod structs;
pub mod winternitz;

use crate::common::zkvm::ZkvmGuest;
use bitcoin::{
    consensus::Decodable,
    hashes::Hash,
    opcodes,
    script::Instruction,
    sighash::{Prevouts, SighashCache, TaprootError},
    Script, TapSighash, TapSighashType, Transaction, TxOut, Txid,
};

use groth16::CircuitGroth16Proof;
use groth16_verifier::CircuitGroth16WithTotalWork;
use k256::{
    ecdsa::signature,
    schnorr::{Signature, VerifyingKey},
};
use lc_proof::lc_proof_verifier;
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use std::{io::Cursor, str::FromStr};
use storage_proof::verify_storage_proofs;
use structs::{BridgeCircuitInput, WatchTowerChallengeTxCommitment};

macro_rules! assert_all_eq {
    ($first:expr, $( $x:expr ),+ ) => {
        $(
            assert_eq!($first, $x, "Assertion failed: {} != {}", stringify!($first), stringify!($x));
        )+
    };
}

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

    let kickoff_tx: Transaction =
        match Decodable::consensus_decode(&mut Cursor::new(&input.kickoff_tx)) {
            Ok(tx) => tx,
            Err(_) => panic!("Invalid kickoff transaction"),
        };

    let kickoff_tx_id = kickoff_tx.compute_txid();

    let (max_total_work, challenge_sending_watchtowers) =
        total_work_and_watchtower_flags(&kickoff_tx, &kickoff_tx_id, &input, &work_only_image_id);

    // Why is that 32 bytes in the first place?
    let total_work: [u8; 16] = input.hcp.chain_state.total_work[16..32]
        .try_into()
        .expect("Cannot fail");

    // If total work is less than the max total work of watchtowers, panic
    if total_work < max_total_work {
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

    let deposit_constant = deposit_constant(
        last_output,
        &kickoff_tx_id,
        &input.watchtower_pubkeys,
        input.sp.txid_hex,
    );

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

/// Converts a compressed Groth16 proof into a proof structure and verifies it against a given image ID.
///
/// # Parameters
///
/// - `compressed_proof`: A reference to a 128-byte array containing the compressed Groth16 proof.
/// - `total_work`: A 16-byte array representing the total accumulated work associated with the proof.
/// - `image_id`: A reference to a 32-byte array representing the image ID used for verification.
///
/// # Returns
///
/// - `true` if the Groth16 proof is successfully deserialized and verified.
/// - `false` if any step in the process fails (e.g., failed deserialization or proof verification).
///
/// # Failure Cases
///
/// - If deserialization of the compressed proof fails, it returns `false`.
/// - If Groth16 proof verification fails, it returns `false`.
fn convert_to_groth16_and_verify(
    compressed_proof: &[u8; 128],
    total_work: [u8; 16],
    image_id: &[u8; 32],
) -> bool {
    let seal = match CircuitGroth16Proof::from_compressed(&compressed_proof) {
        Ok(seal) => seal,
        Err(_) => return false,
    };

    let groth16_proof = CircuitGroth16WithTotalWork::new(seal, total_work);
    groth16_proof.verify(image_id)
}

/// Verifies watchtower challenge transactions and collects their outputs.
///
/// This function performs validation on a set of watchtower challenge transactions
/// and their associated inputs, witnesses, and public keys. It checks that:
/// - Each challenge input corresponds to the correct `kickoff_tx` output (P2TR),
/// - The signature is valid under the Taproot sighash rules,
/// - The public key matches the one registered for the watchtower,
/// - And, if all checks pass, it marks the corresponding bit in a 20-byte bitmap
///   (`challenge_sending_watchtowers`) and collects the first 3 outputs of the
///   watchtower transaction into `watchtower_challenges_outputs`.
///
/// # Parameters
/// - `circuit_input`: Data structure holding serialized watchtower transactions, UTXOs, input indices, and pubkeys.
/// - `kickoff_tx`: The corresponding kickoff transaction used to validate the watchtower inputs.
/// - `kickoff_tx_id`: The transaction ID of the `kickoff_tx`.
///
/// # Returns
/// A tuple containing:
/// - A 20-byte bitmap indicating which watchtower challenges were valid,
/// - A vector of the first 3 outputs from each valid watchtower transaction.
///
/// # Notes
/// Invalid or malformed challenge data (e.g., decoding errors, invalid signatures)
/// will be skipped gracefully without causing the function to panic.
fn verify_watchtower_challenges(
    circuit_input: &BridgeCircuitInput,
    kickoff_tx: &Transaction,
    kickoff_tx_id: &Txid,
) -> ([u8; 20], Vec<[TxOut; 3]>) {
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];
    let mut watchtower_challenges_outputs: Vec<[TxOut; 3]> = vec![];

    // num_watchtowers should be removed, does not make sense to have it
    assert_all_eq!(
        circuit_input.watchtower_challenge_txs.len(),
        circuit_input.watchtower_challenge_utxos.len(),
        circuit_input.watchtower_challenge_input_idxs.len(),
        circuit_input.watchtower_idxs.len(),
        circuit_input.num_watchtowers as usize
    );

    for (_, (((tx, &idx), utxos), input_idx)) in circuit_input
        .watchtower_challenge_txs
        .iter()
        .zip(circuit_input.watchtower_idxs.iter())
        .zip(circuit_input.watchtower_challenge_utxos.iter())
        .zip(circuit_input.watchtower_challenge_input_idxs.iter())
        .enumerate()
    {
        let Ok(watchtower_tx): Result<Transaction, _> =
            Decodable::consensus_decode(&mut Cursor::new(tx))
        else {
            continue;
        };

        let Ok(outputs): Result<Vec<TxOut>, _> = utxos
            .iter()
            .map(|utxo| Decodable::consensus_decode(&mut Cursor::new(utxo)))
            .collect::<Result<_, _>>()
        else {
            continue;
        };

        let prevouts = Prevouts::All(&outputs);

        if watchtower_tx.input.len() <= *input_idx as usize {
            continue;
        }

        let input = watchtower_tx.input[*input_idx as usize].clone();

        let witness = input.witness.to_vec();

        if witness.len() != 1 {
            continue;
        }

        let (sighash_type, sig_bytes): (TapSighashType, [u8; 64]) = {
            if witness[0].len() == 64 {
                (
                    TapSighashType::Default,
                    witness[0][0..64].try_into().expect("Cannot fail"),
                )
            } else if witness[0].len() == 65 {
                match TapSighashType::from_consensus_u8(witness[0][64]) {
                    Ok(sighash_type) => (
                        sighash_type,
                        witness[0][0..64].try_into().expect("Cannot fail"),
                    ),
                    Err(_) => continue,
                }
            } else {
                continue;
            }
        };

        let sighash = match sighash(&watchtower_tx, &prevouts, *input_idx as usize, sighash_type) {
            Ok(sighash) => sighash,
            Err(_) => continue,
        };

        if input.previous_output.txid != *kickoff_tx_id
            || kickoff_tx.output.len() <= input.previous_output.vout as usize
        {
            continue;
        };

        let output = kickoff_tx.output[input.previous_output.vout as usize].clone();

        let pubkey = output.script_pubkey.clone();

        // IS THIS CHECK CORRECT?
        if !pubkey.is_p2tr() {
            continue;
        };

        // IS THIS CHECK CORRECT?
        if circuit_input.watchtower_pubkeys[idx as usize] != pubkey.as_bytes()[2..34] {
            continue;
        }

        let verifying_key = match VerifyingKey::from_bytes(&pubkey.as_bytes()[2..]) {
            Ok(verifying_key) => verifying_key,
            Err(_) => continue,
        };

        let signature = match Signature::try_from(sig_bytes.as_slice()) {
            Ok(signature) => signature,
            Err(_) => continue,
        };

        if IS_TEST
            || verifying_key
                .verify_prehash(sighash.as_byte_array(), &signature)
                .is_ok()
        {
            // TODO: CHECK IF THIS IS CORRECT
            challenge_sending_watchtowers[(idx as usize) / 8] |= 1 << (idx % 8);
            if watchtower_tx.output.len() >= 3 {
                watchtower_challenges_outputs.push([
                    watchtower_tx.output[0].clone(),
                    watchtower_tx.output[1].clone(),
                    watchtower_tx.output[2].clone(),
                ]);
            }
        }
    }

    (challenge_sending_watchtowers, watchtower_challenges_outputs)
}

/// Computes the maximum verified total work and watchtower challenge flags from challenge transactions.
///
/// # Parameters
///
/// - `kickoff_tx`: The kickoff transaction used as a reference for validating watchtower inputs.
/// - `kickoff_tx_id`: The transaction ID of the kickoff transaction.
/// - `watchtower_idxs`: A list of indices corresponding to each watchtower.
/// - `watchtower_challenge_txs`: A list of encoded watchtower challenge transactions.
/// - `watchtower_challenge_utxos`: A list of UTXO sets corresponding to the inputs of the challenge transactions.
/// - `watchtower_challenge_input_idxs`: A list of input indices pointing to which input in each transaction should be verified.
/// - `watchtower_pubkeys`: A list of 32-byte x-only public keys expected from each watchtower (used for P2TR signature verification).
/// - `work_only_image_id`: A 32-byte identifier used for Groth16 verification against the work-only circuit.
///
/// # Returns
///
/// A tuple containing:
/// - `[u8; 16]`: The total work from the highest valid watchtower challenge (after successful Groth16 verification).
/// - `[u8; 20]`: Bitflags representing which watchtowers sent valid challenges (1 bit per watchtower).
///
/// # Panics
///
/// - Panics if the lengths of any of the provided watchtower lists are mismatched.
///
/// # Notes
///
/// - Skips over any challenge with invalid encoding, invalid signature, or improper structure.
/// - Each watchtower challenge is expected to contain exactly 3 outputs:
///     - First two should be P2TR outputs containing the compressed Groth16 proof parts.
///     - Third must be an OP_RETURN containing the rest of the proof and the total work value.
/// - The function sorts valid commitments by total work and verifies the highest one using a Groth16 verifier.
pub fn total_work_and_watchtower_flags(
    kickoff_tx: &Transaction,
    kickoff_tx_id: &Txid,
    circuit_input: &BridgeCircuitInput,
    work_only_image_id: &[u8; 32],
) -> ([u8; 16], [u8; 20]) {
    let (challenge_sending_watchtowers, watchtower_challenges_outputs) =
        verify_watchtower_challenges(circuit_input, kickoff_tx, kickoff_tx_id);

    let mut valid_watchtower_challenge_commitments: Vec<WatchTowerChallengeTxCommitment> = vec![];

    for outputs in watchtower_challenges_outputs {
        if !outputs[0].script_pubkey.is_p2tr()
            || !outputs[1].script_pubkey.is_p2tr()
            || !outputs[2].script_pubkey.is_op_return()
        {
            continue;
        }

        let first_output: [u8; 32] = outputs[0].script_pubkey.to_bytes()[2..]
            .try_into()
            .expect("Cannot fail");
        let second_output: [u8; 32] = outputs[1].script_pubkey.to_bytes()[2..]
            .try_into()
            .expect("Cannot fail");

        let Some(Ok(third_output)) =
            parse_op_return_data(&outputs[2].script_pubkey).map(TryInto::<[u8; 80]>::try_into)
        else {
            continue;
        };

        let compressed_g16_proof: [u8; 128] = [&first_output, &second_output, &third_output[0..64]]
            .concat()
            .try_into()
            .expect("Cannot fail");

        let total_work: [u8; 16] = third_output[64..].try_into().expect("Cannot fail");
        let commitment = WatchTowerChallengeTxCommitment {
            compressed_g16_proof: compressed_g16_proof.try_into().expect("Cannot fail"),
            total_work: total_work,
        };

        valid_watchtower_challenge_commitments.push(commitment);
    }

    // TODO: UPDATE THIS PART ACCORDING TO ENDIANNESS
    valid_watchtower_challenge_commitments.sort_by(|a, b| b.total_work.cmp(&a.total_work));

    let mut total_work = [0u8; 16];

    for commitment in valid_watchtower_challenge_commitments {
        // Grooth16 verification of work only circuit
        if IS_TEST
            || convert_to_groth16_and_verify(
                &commitment.compressed_g16_proof,
                commitment.total_work,
                work_only_image_id,
            )
        {
            total_work = commitment.total_work;
            break;
        }
    }

    (total_work, challenge_sending_watchtowers)
}

fn parse_op_return_data(script: &Script) -> Option<Vec<u8>> {
    let mut instructions = script.instructions();
    if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
        if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
            return Some(data.as_bytes().to_vec());
        }
    }
    None
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
    kickoff_tx: &Txid,
    watchtower_pubkeys: &[Vec<u8>],
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

    // pubkeys are 32 bytes long
    let pubkey_concat = watchtower_pubkeys
        .iter()
        .flat_map(|pubkey| pubkey.to_vec())
        .collect::<Vec<u8>>();

    let watchtower_pubkeys_digest: [u8; 32] = Sha256::digest(&pubkey_concat).into();
    let pre_deposit_constant = [
        kickoff_tx.to_byte_array(),
        move_txid_hex,
        watchtower_pubkeys_digest,
        operator_id,
    ]
    .concat();

    Sha256::digest(&pre_deposit_constant).into()
}

fn sighash(
    wt_tx: &Transaction,
    prevouts: &Prevouts<TxOut>,
    input_index: usize,
    sighash_type: TapSighashType,
) -> Result<TapSighash, TaprootError> {
    SighashCache::new(wt_tx).taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
}

#[cfg(test)]
mod tests {

    use crate::bridge_circuit::structs::{LightClientProof, StorageProof};

    use super::*;
    use bitcoin::{
        consensus::{Decodable, Encodable},
        ScriptBuf, Transaction,
    };
    use final_spv::{merkle_tree::BlockInclusionProof, spv::SPV, transaction::CircuitTransaction};
    use header_chain::{
        header_chain::{BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader},
        mmr_native::MMRInclusionProof,
    };
    use lazy_static::lazy_static;
    use risc0_zkvm::compute_image_id;

    const WORK_ONLY_ELF: &[u8; 154116] =
        include_bytes!("../../../risc0-circuits/elfs/testnet4-work-only-guest");

    lazy_static! {
        static ref WORK_ONLY_IMAGE_ID: [u8; 32] = compute_image_id(WORK_ONLY_ELF)
            .expect("Elf must be valid")
            .as_bytes()
            .try_into()
            .expect("Elf must be valid");
    }

    #[test]
    fn test_total_work_and_watchtower_flags() {
        let wt_tx_bytes = include_bytes!("../../test_data/wt_raw_tx.bin");
        let kickoff_raw_tx_bytes = include_bytes!("../../test_data/kickoff_raw_tx.bin");
        let pubkey = "412c00124e48ab8b082a5fa3ee742eb763387ef67adb9f0d5405656ff12ffd50";

        let pubkey = hex::decode(pubkey).unwrap();

        let wt_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&wt_tx_bytes)).unwrap();

        let kickoff_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&kickoff_raw_tx_bytes))
                .expect("Failed to decode kickoff tx");

        let kickoff_tx_id = kickoff_tx.compute_txid();

        let output = kickoff_tx.output[wt_tx.input[0].previous_output.vout as usize].clone();

        // READ FROM THE FILE TO PREVENT THE ISSUE WITH ELF - IMAGE ID UPDATE CYCLE

        let mut encoded_tx_out = vec![];
        let _ = Encodable::consensus_encode(&output, &mut encoded_tx_out);

        let mut watchtower_pubkeys = vec![vec![0u8]; 160];

        let operator_idx: u8 = 50;

        watchtower_pubkeys[operator_idx as usize] = pubkey;

        let input = BridgeCircuitInput {
            kickoff_tx: kickoff_raw_tx_bytes.to_vec(),
            watchtower_idxs: vec![operator_idx],
            watchtower_pubkeys: watchtower_pubkeys,
            watchtower_challenge_input_idxs: vec![0],
            watchtower_challenge_utxos: vec![vec![encoded_tx_out]],
            watchtower_challenge_txs: vec![wt_tx_bytes.to_vec()],
            hcp: BlockHeaderCircuitOutput {
                method_id: [0; 8],
                chain_state: ChainState::new(),
            },
            payout_spv: SPV {
                transaction: CircuitTransaction(wt_tx),
                block_inclusion_proof: BlockInclusionProof::new(0, vec![]),
                block_header: CircuitBlockHeader {
                    version: 0,
                    prev_block_hash: [0u8; 32],
                    merkle_root: [0u8; 32],
                    time: 0,
                    bits: 0,
                    nonce: 0,
                },
                mmr_inclusion_proof: MMRInclusionProof {
                    subroot_idx: 0,
                    internal_idx: 0,
                    inclusion_proof: vec![],
                },
            },
            lcp: LightClientProof::default(),
            sp: StorageProof::default(),
            num_watchtowers: 1,
        };

        let (total_work, challenge_sending_watchtowers) = total_work_and_watchtower_flags(
            &kickoff_tx,
            &kickoff_tx_id,
            &input,
            &WORK_ONLY_IMAGE_ID,
        );

        let expected_challenge_sending_watchtowers =
            [0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            challenge_sending_watchtowers, expected_challenge_sending_watchtowers,
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    fn test_parse_op_return_data() {
        let op_return_data = "6a4c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let script = ScriptBuf::from(hex::decode(op_return_data).unwrap());
        assert!(script.is_op_return(), "Script is not OP_RETURN");
        let parsed_data = parse_op_return_data(&script).expect("Failed to parse OP_RETURN data");
        assert_eq!(parsed_data, [0u8; 80], "Parsed data is not correct");
    }
}
