pub mod constants;
pub mod groth16;
pub mod groth16_verifier;
pub mod lc_proof;
pub mod storage_proof;
pub mod structs;
pub mod winternitz;

use crate::common::zkvm::ZkvmGuest;
use bitcoin::{
    hashes::Hash,
    opcodes,
    script::Instruction,
    sighash::{Prevouts, SighashCache, TaprootError},
    Script, TapSighash, TapSighashType, Transaction, TxOut, Txid,
};

use core::panic;
use groth16::CircuitGroth16Proof;
use groth16_verifier::CircuitGroth16WithTotalWork;
use k256::{
    ecdsa::signature,
    schnorr::{Signature, VerifyingKey},
};
use lc_proof::lc_proof_verifier;
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use std::str::FromStr;
use storage_proof::verify_storage_proofs;
use structs::{BridgeCircuitInput, WatchTowerChallengeTxCommitment, WatchtowerChallengeSet};

pub const MAINNET: [u32; 8] = [
    2676188327, 45512797, 2023835249, 3297151795, 2340552790, 1016661468, 2312535365, 3209566978,
];

pub const TESTNET4: [u32; 8] = [
    1999769151, 1443988293, 220822608, 619344254, 441227906, 2886402800, 2598360110, 4027896753,
];

pub const SIGNET: [u32; 8] = [
    2300710338, 3187252785, 186764044, 1017001434, 1319849149, 2675930120, 2623779719, 212634249,
];

pub const REGTEST: [u32; 8] = [
    1617243068, 4152866222, 106734300, 3669652093, 3974475181, 104860470, 2574174140, 2407777988,
];

/// The method ID for the header chain circuit.
pub const HEADER_CHAIN_METHOD_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET,
        Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET4,
        Some(network) if matches!(network.as_bytes(), b"signet") => SIGNET,
        Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST,
        None => MAINNET,
        _ => panic!("Invalid network type"),
    }
};

const NUMBER_OF_WATCHTOWERS: usize = 160;

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

    let kickoff_txid = input.kickoff_tx.compute_txid(); // TODO: Maybe use `txid` instead of `compute_txid`

    let (max_total_work, challenge_sending_watchtowers) =
        total_work_and_watchtower_flags(&kickoff_txid, &input, &work_only_image_id);

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
    let (user_wd_outpoint_str, move_tx_id) = verify_storage_proofs(&input.sp, state_root);

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
        &kickoff_txid,
        &input.all_watchtower_pubkeys,
        move_tx_id,
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
    let seal = match CircuitGroth16Proof::from_compressed(compressed_proof) {
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
///   Note: This function only verifies keypath spends.
///
/// # Parameters
/// - `circuit_input`: Data structure holding serialized watchtower transactions, UTXOs, input indices, and pubkeys.
/// - `kickoff_tx`: The corresponding kickoff transaction used to validate the watchtower inputs.
/// - `kickoff_txid`: The transaction ID of the `kickoff_tx`.
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
    kickoff_txid: &Txid,
) -> WatchtowerChallengeSet {
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];
    let mut watchtower_challenges_outputs: Vec<[TxOut; 3]> = vec![];

    // let &BridgeCircuitInput {
    //     watchtower_inputs:
    //         WatchtowerInputs {
    //             watchtower_challenge_txs: ref challenge_txs,
    //             watchtower_challenge_utxos: ref challenge_utxos,
    //             watchtower_challenge_input_idxs: ref challenge_input_idxs,
    //             watchtower_challenge_witnesses: ref challenge_witnesses,
    //             ref watchtower_idxs,
    //             ref watchtower_pubkeys,
    //         },
    //     kickoff_tx: ref _kickoff_tx_bytes,
    //     hcp: ref _hcp,
    //     payout_spv: ref _payout_spv,
    //     lcp: ref _lcp,
    //     sp: ref _sp,
    // } = circuit_input;

    if circuit_input.watchtower_inputs.len() > NUMBER_OF_WATCHTOWERS {
        panic!("Invalid number of watchtower challenge transactions");
    }

    // assert_all_eq!(
    //     challenge_txs.len(),
    //     challenge_utxos.len(),
    //     challenge_input_idxs.len(),
    //     watchtower_idxs.len(),
    //     challenge_witnesses.len()
    // );

    // for ((((tx, &idx), utxos), input_idx), intput_witness) in challenge_txs
    //     .iter()
    //     .zip(watchtower_idxs.iter())
    //     .zip(challenge_utxos.iter())
    //     .zip(challenge_input_idxs.iter())
    //     .zip(challenge_witnesses.iter())
    for watchtower_input in circuit_input.watchtower_inputs.iter() {
        // let Ok(watchtower_tx): Result<Transaction, _> =
        //     Decodable::consensus_decode(&mut Cursor::new(tx))
        // else {
        //     panic!(
        //         "Invalid watchtower challenge transaction, watchtower index: {}",
        //         idx
        //     );
        // };

        // let Ok(outputs): Result<Vec<TxOut>, _> = watchtower_input.watchtower_challenge_utxos
        //     .iter()
        //     .map(|utxo| deserialize_txout(reader))
        //     .collect::<Result<_, _>>()
        // else {
        //     panic!(
        //         "Invalid watchtower challenge UTXOs, watchtower index: {}",
        //         idx
        //     );
        // };

        let inner_txouts: Vec<TxOut> = watchtower_input
            .watchtower_challenge_utxos
            .iter()
            .map(|utxo| utxo.0.clone()) // TODO: Get rid of this clone if possible
            .collect::<Vec<TxOut>>();

        let prevouts = Prevouts::All(&inner_txouts);

        if watchtower_input.watchtower_challenge_tx.input.len()
            <= watchtower_input.watchtower_challenge_input_idx as usize
        {
            panic!(
                "Invalid watchtower tx input index, watchtower index: {}",
                watchtower_input.watchtower_challenge_input_idx
            );
        }

        let (sighash_type, sig_bytes): (TapSighashType, [u8; 64]) = {
            if watchtower_input.watchtower_challenge_witness.len() != 1 {
                panic!(
                    "Invalid witness length, expected 1 witness, watchtower index: {}",
                    watchtower_input.watchtower_challenge_input_idx
                );
            }
            let signature = watchtower_input
                .watchtower_challenge_witness
                .nth(0)
                .unwrap();
            if signature.len() == 64 {
                (
                    TapSighashType::Default,
                    signature[0..64].try_into().expect("Cannot fail"),
                )
            } else if signature.len() == 65 {
                match TapSighashType::from_consensus_u8(signature[64]) {
                    Ok(sighash_type) => (
                        sighash_type,
                        signature[0..64].try_into().expect("Cannot fail"),
                    ),
                    Err(_) => panic!(
                        "Invalid sighash type, watchtower index: {}",
                        watchtower_input.watchtower_challenge_input_idx
                    ),
                }
            } else {
                panic!(
                    "Invalid witness length, expected 64 or 65 bytes, watchtower index: {}",
                    watchtower_input.watchtower_challenge_input_idx
                );
            }
        };

        let Ok(sighash) = sighash(
            &watchtower_input.watchtower_challenge_tx,
            &prevouts,
            watchtower_input.watchtower_challenge_input_idx as usize,
            sighash_type,
        ) else {
            panic!(
                "Sighash could not be computed, watchtower index: {}",
                watchtower_input.watchtower_challenge_input_idx
            );
        };

        let input = watchtower_input.watchtower_challenge_tx.input
            [watchtower_input.watchtower_challenge_input_idx as usize]
            .clone();

        if input.previous_output.txid != *kickoff_txid
            || circuit_input.kickoff_tx.output.len() <= input.previous_output.vout as usize
        {
            panic!(
                "Invalid input: expected input to reference an output from the kickoff transaction (txid: {}), but got txid: {}, vout: {}",
                kickoff_txid,
                input.previous_output.txid,
                input.previous_output.vout
            );
        };

        let output = circuit_input.kickoff_tx.output[input.previous_output.vout as usize].clone();

        let script_pubkey = output.script_pubkey.clone();

        if !script_pubkey.is_p2tr() {
            panic!(
                "Invalid output script type - kickoff, watchtower index: {}",
                watchtower_input.watchtower_challenge_input_idx
            );
        };

        if watchtower_input.watchtower_challenge_input_idx as usize
            >= circuit_input.all_watchtower_pubkeys.len()
        {
            panic!(
                "Invalid watchtower index, watchtower index: {}, number of watchtowers: {}",
                watchtower_input.watchtower_challenge_input_idx,
                circuit_input.all_watchtower_pubkeys.len()
            );
        }

        if circuit_input.all_watchtower_pubkeys
            [watchtower_input.watchtower_challenge_input_idx as usize]
            != script_pubkey.as_bytes()[2..34]
        {
            panic!(
                "Invalid watchtower public key, watchtower index: {}",
                watchtower_input.watchtower_challenge_input_idx
            );
        }

        let Ok(verifying_key) = VerifyingKey::from_bytes(&script_pubkey.as_bytes()[2..]) else {
            panic!(
                "Invalid verifying key, watchtower index: {}",
                watchtower_input.watchtower_challenge_input_idx
            );
        };

        let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
            panic!(
                "Invalid signature, watchtower index: {}",
                watchtower_input.watchtower_challenge_input_idx
            );
        };

        if IS_TEST
            || verifying_key
                .verify_prehash(sighash.as_byte_array(), &signature)
                .is_ok()
        {
            // TODO: CHECK IF THIS IS CORRECT
            challenge_sending_watchtowers
                [(watchtower_input.watchtower_challenge_input_idx as usize) / 8] |=
                1 << (watchtower_input.watchtower_challenge_input_idx % 8);
            if watchtower_input.watchtower_challenge_tx.output.len() >= 3 {
                watchtower_challenges_outputs.push([
                    watchtower_input.watchtower_challenge_tx.output[0].clone(),
                    watchtower_input.watchtower_challenge_tx.output[1].clone(),
                    watchtower_input.watchtower_challenge_tx.output[2].clone(),
                ]);
            }
        }
    }

    WatchtowerChallengeSet {
        challenge_senders: challenge_sending_watchtowers,
        challenge_outputs: watchtower_challenges_outputs,
    }
}

/// Computes the maximum verified total work and watchtower challenge flags from challenge transactions.
///
/// # Parameters
///
/// - `kickoff_tx`: The kickoff transaction used as a reference for validating watchtower inputs.
/// - `kickoff_txid`: The transaction ID of the kickoff transaction.
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
    kickoff_txid: &Txid,
    circuit_input: &BridgeCircuitInput,
    work_only_image_id: &[u8; 32],
) -> ([u8; 16], [u8; 20]) {
    let watchtower_challenge_set = verify_watchtower_challenges(circuit_input, kickoff_txid);

    let mut valid_watchtower_challenge_commitments: Vec<WatchTowerChallengeTxCommitment> = vec![];

    for outputs in watchtower_challenge_set.challenge_outputs {
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
            compressed_g16_proof,
            total_work,
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

    (total_work, watchtower_challenge_set.challenge_senders)
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
    SighashCache::new(wt_tx).taproot_key_spend_signature_hash(input_index, prevouts, sighash_type)
}

#[cfg(test)]
mod tests {
    use super::{
        structs::{CircuitTxOut, CircuitWitness, WatchtowerInput},
        *,
    };
    use crate::bridge_circuit::structs::{LightClientProof, StorageProof};
    use bitcoin::{
        absolute::Height,
        consensus::{Decodable, Encodable},
        transaction::Version,
        ScriptBuf, Transaction, Witness,
    };
    use final_spv::{merkle_tree::BlockInclusionProof, spv::SPV, transaction::CircuitTransaction};
    use header_chain::{
        header_chain::{BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader},
        mmr_native::MMRInclusionProof,
    };
    use lazy_static::lazy_static;
    use risc0_zkvm::compute_image_id;
    use std::io::Cursor;

    const WORK_ONLY_ELF: &[u8] =
        include_bytes!("../../../risc0-circuits/elfs/testnet4-work-only-guest.bin");

    lazy_static! {
        static ref WORK_ONLY_IMAGE_ID: [u8; 32] = compute_image_id(WORK_ONLY_ELF)
            .expect("Elf must be valid")
            .as_bytes()
            .try_into()
            .expect("Elf must be valid");
    }

    fn total_work_and_watchtower_flags_setup() -> (BridgeCircuitInput, Txid) {
        let wt_tx_bytes = include_bytes!("../../test_data/wt_raw_tx.bin");
        let kickoff_raw_tx_bytes = include_bytes!("../../test_data/kickoff_raw_tx.bin");
        let pubkey = "412c00124e48ab8b082a5fa3ee742eb763387ef67adb9f0d5405656ff12ffd50";

        let pubkey = hex::decode(pubkey).unwrap();

        let mut wt_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&wt_tx_bytes)).unwrap();

        wt_tx.input[0].witness.clear();

        let kickoff_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&kickoff_raw_tx_bytes))
                .expect("Failed to decode kickoff tx");

        let kickoff_txid = kickoff_tx.compute_txid();

        let output = kickoff_tx.output[wt_tx.input[0].previous_output.vout as usize].clone();

        // READ FROM THE FILE TO PREVENT THE ISSUE WITH ELF - IMAGE ID UPDATE CYCLE
        let mut encoded_tx_out = vec![];
        let _ = Encodable::consensus_encode(&output, &mut encoded_tx_out);

        let tx_out = Decodable::consensus_decode(&mut Cursor::new(&encoded_tx_out))
            .expect("Failed to decode kickoff tx");

        let mut watchtower_pubkeys = vec![vec![0u8]; 160];

        let operator_idx: u8 = 50;

        watchtower_pubkeys[operator_idx as usize] = pubkey.clone();

        let input = BridgeCircuitInput {
            kickoff_tx: CircuitTransaction(kickoff_tx.clone()),
            watchtower_inputs: vec![WatchtowerInput {
                watchtower_idx: operator_idx,
                watchtower_challenge_witness: CircuitWitness(wt_tx.input[0].witness.clone()),
                watchtower_challenge_input_idx: 0,
                watchtower_challenge_utxos: vec![CircuitTxOut(tx_out)],
                watchtower_challenge_tx: CircuitTransaction(wt_tx.clone()),
            }],
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
            all_watchtower_pubkeys: vec![pubkey],
        };

        (input, kickoff_txid)
    }

    #[test]
    fn test_total_work_and_watchtower_flags() {
        let (input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        let (total_work, challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);

        let expected_challenge_sending_watchtowers =
            [0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            challenge_sending_watchtowers, expected_challenge_sending_watchtowers,
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    fn test_total_work_and_watchtower_flags_incorrect_witness() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        let mut new_witness = Witness::new();
        new_witness.push([0x00]);
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(new_witness);

        let (total_work, challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);

        assert_eq!(total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            challenge_sending_watchtowers, [0u8; 20],
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    fn test_total_work_and_watchtower_flags_incorrect_tx() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        input.watchtower_inputs[0].watchtower_challenge_tx = CircuitTransaction(Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::from_consensus(0).unwrap()),
            input: vec![],
            output: vec![],
        });

        let (total_work, challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);

        assert_eq!(total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            challenge_sending_watchtowers, [0u8; 20],
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower challenge input index")]
    fn test_total_work_and_watchtower_flags_tx_in_incorrect_format() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Create invalid transaction with no inputs
        input.watchtower_inputs[0].watchtower_challenge_tx = CircuitTransaction(Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::from_consensus(0).unwrap()),
            input: vec![],
            output: vec![],
        });

        // Keep the input index at 0, which would now be invalid
        input.watchtower_inputs[0].watchtower_challenge_input_idx = 0;

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid witness length")]
    fn test_total_work_and_watchtower_flags_utxo_in_invalid_format() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Create a witness with more than one item, which would be invalid
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0x00]);
        invalid_witness.push([0x01]);
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower public key")]
    fn test_total_work_and_watchtower_flags_invalid_pubkey() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Modify the all_watchtower_pubkeys (the array that's actually used in the new code)
        input.all_watchtower_pubkeys[0] = vec![0u8; 32];

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower challenge input index")]
    fn test_total_work_and_watchtower_flags_invalid_wt_index() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Set an invalid index that's out of bounds
        input.watchtower_inputs[0].watchtower_challenge_input_idx = 160;

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower challenge input index")]
    fn test_total_work_and_watchtower_flags_invalid_wt_input_index() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Set an input index that's beyond the transaction's inputs
        input.watchtower_inputs[0].watchtower_challenge_input_idx = 10;

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid witness length, expected 64 or 65 bytes")]
    fn test_total_work_and_watchtower_flags_invalid_witness() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Create an invalid witness with 65 bytes but all zeros (signature validation will fail)
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0u8; 63]); // 63 bytes instead of 64/65
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid signature")]
    fn test_total_work_and_watchtower_flags_invalid_witness_2() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Create an invalid witness with 64 bytes but all zeros (signature validation will fail)
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0u8; 64]);
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid witness length, expected 64 or 65 bytes")]
    fn test_total_work_and_watchtower_flags_invalid_witness_length() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        // Create an invalid witness with incorrect length
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0u8; 60]); // Not 64 or 65 bytes
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&kickoff_txid, &input, &WORK_ONLY_IMAGE_ID);
    }

    #[test]
    fn test_parse_op_return_data() {
        let op_return_data = "6a4c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let script = ScriptBuf::from(hex::decode(op_return_data).unwrap());
        assert!(script.is_op_return(), "Script is not OP_RETURN");
        let parsed_data = parse_op_return_data(&script).expect("Failed to parse OP_RETURN data");
        assert_eq!(parsed_data, [0u8; 80], "Parsed data is not correct");
    }

    #[test]
    fn test_parse_op_return_data_short() {
        let op_return_data = "6a09000000000000000000";
        let script = ScriptBuf::from(hex::decode(op_return_data).unwrap());
        assert!(script.is_op_return(), "Script is not OP_RETURN");
        let parsed_data = parse_op_return_data(&script).expect("Failed to parse OP_RETURN data");
        assert_eq!(parsed_data, [0u8; 9], "Parsed data is not correct");
    }

    #[test]
    fn test_parse_op_return_data_fail() {
        let op_return_data = "6a4c4f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let script = ScriptBuf::from(hex::decode(op_return_data).unwrap());
        assert!(script.is_op_return(), "Script is not OP_RETURN");
        let parsed_data = parse_op_return_data(&script).expect("Failed to parse OP_RETURN data");
        assert_ne!(parsed_data, [0u8; 80], "Parsed data should not be correct");
    }
}
