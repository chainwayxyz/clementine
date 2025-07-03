pub mod constants;
pub mod groth16;
pub mod groth16_verifier;
pub mod lc_proof;
pub mod merkle_tree;
pub mod spv;
pub mod storage_proof;
pub mod structs;
pub mod transaction;

use crate::common::{
    constants::{
        MAINNET_HEADER_CHAIN_METHOD_ID, MAX_NUMBER_OF_WATCHTOWERS, REGTEST_HEADER_CHAIN_METHOD_ID,
        SIGNET_HEADER_CHAIN_METHOD_ID, TESTNET4_HEADER_CHAIN_METHOD_ID,
    },
    zkvm::ZkvmGuest,
};
use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    io::{self},
    opcodes,
    script::Instruction,
    sighash::{Prevouts, PrevoutsIndexError, SighashCache},
    Script, TapLeafHash, TapSighash, TapSighashType, Transaction, TxOut,
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
use std::borrow::{Borrow, BorrowMut};
use storage_proof::verify_storage_proofs;
use structs::{
    BridgeCircuitInput, ChallengeSendingWatchtowers, DepositConstant, LatestBlockhash,
    PayoutTxBlockhash, TotalWork, WatchTowerChallengeTxCommitment, WatchtowerChallengeSet,
};

/// The method ID for the header chain circuit.
pub const HEADER_CHAIN_METHOD_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET_HEADER_CHAIN_METHOD_ID,
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            TESTNET4_HEADER_CHAIN_METHOD_ID
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => SIGNET_HEADER_CHAIN_METHOD_ID,
        Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST_HEADER_CHAIN_METHOD_ID,
        None => MAINNET_HEADER_CHAIN_METHOD_ID,
        _ => panic!("Invalid network type"),
    }
};

/// Executes the bridge circuit in a zkVM environment, verifying multiple cryptographic proofs
/// related to watchtowers' Bitcoin work, SPV, and storage proofs.
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
    assert_eq!(
        HEADER_CHAIN_METHOD_ID, input.hcp.method_id,
        "Invalid method ID for header chain circuit: expected {:?}, got {:?}",
        HEADER_CHAIN_METHOD_ID, input.hcp.method_id
    );

    // Verify the HCP
    guest.verify(input.hcp.method_id, &input.hcp);

    let (max_total_work, challenge_sending_watchtowers) =
        total_work_and_watchtower_flags(&input, &work_only_image_id);

    // Why is that 32 bytes in the first place?
    let total_work: TotalWork = input.hcp.chain_state.total_work[16..32]
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
    let mmr = input.hcp.chain_state.block_hashes_mmr.clone();

    if !input.payout_spv.verify(mmr) {
        panic!("Invalid SPV proof");
    }

    // Light client proof verification
    let light_client_circuit_output = lc_proof_verifier(input.lcp.clone());

    // Storage proof verification for deposit tx index and withdrawal outpoint
    let (user_wd_outpoint, vout, move_txid) =
        verify_storage_proofs(&input.sp, light_client_circuit_output.l2_state_root);

    let user_wd_txid = bitcoin::Txid::from_byte_array(*user_wd_outpoint);

    let payout_input_index: usize = input.payout_input_index as usize;

    assert_eq!(
        user_wd_txid,
        input.payout_spv.transaction.input[payout_input_index]
            .previous_output
            .txid,
        "Invalid withdrawal transaction ID"
    );

    assert_eq!(
        vout,
        input.payout_spv.transaction.input[payout_input_index]
            .previous_output
            .vout,
        "Invalid withdrawal transaction output index"
    );

    let last_output = input.payout_spv.transaction.output.last().unwrap();

    let round_txid = input.kickoff_tx.input[0]
        .previous_output
        .txid
        .to_byte_array();
    let kickoff_round_vout = input.kickoff_tx.input[0].previous_output.vout;

    let operator_xonlypk: [u8; 32] = parse_op_return_data(&last_output.script_pubkey)
        .expect("Invalid operator xonlypk")
        .try_into()
        .expect("Invalid xonlypk");

    let deposit_constant = deposit_constant(
        operator_xonlypk,
        input.watchtower_challenge_connector_start_idx,
        &input.all_tweaked_watchtower_pubkeys,
        *move_txid,
        round_txid,
        kickoff_round_vout,
        input.hcp.genesis_state_hash,
    );

    // In the future this will be fetched from the LC proof
    let latest_blockhash: LatestBlockhash = input.hcp.chain_state.best_block_hash[12..32]
        .try_into()
        .unwrap();
    let payout_tx_blockhash: PayoutTxBlockhash = input.payout_spv.block_header.compute_block_hash()
        [12..32]
        .try_into()
        .unwrap();

    let journal_hash = journal_hash(
        payout_tx_blockhash,
        latest_blockhash,
        challenge_sending_watchtowers,
        deposit_constant,
    );

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
    genesis_state_hash: [u8; 32],
) -> bool {
    let seal = match CircuitGroth16Proof::from_compressed(compressed_proof) {
        Ok(seal) => seal,
        Err(_) => return false,
    };

    let groth16_proof = CircuitGroth16WithTotalWork::new(seal, total_work, genesis_state_hash);
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
pub fn verify_watchtower_challenges(circuit_input: &BridgeCircuitInput) -> WatchtowerChallengeSet {
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];
    let mut watchtower_challenges_outputs: Vec<Vec<TxOut>> = vec![];

    let kickoff_txid = circuit_input.kickoff_tx.compute_txid();

    if circuit_input.watchtower_inputs.len() > MAX_NUMBER_OF_WATCHTOWERS {
        panic!("Invalid number of watchtower challenge transactions");
    }

    for watchtower_input in circuit_input.watchtower_inputs.iter() {
        let inner_txouts: Vec<TxOut> = watchtower_input
            .watchtower_challenge_utxos
            .iter()
            .map(|utxo| utxo.0.clone())
            .collect::<Vec<TxOut>>();

        let prevouts = Prevouts::All(&inner_txouts);

        let watchtower_input_idx = watchtower_input.watchtower_challenge_input_idx as usize;

        if watchtower_input_idx >= watchtower_input.watchtower_challenge_tx.input.len() {
            panic!(
                "Invalid watchtower challenge input index, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        }

        let input = watchtower_input.watchtower_challenge_tx.input[watchtower_input_idx].clone();

        let (sighash_type, sig_bytes): (TapSighashType, [u8; 64]) = {
            // Enforce the witness to be only 1 element, which is the signature
            if watchtower_input.watchtower_challenge_witness.0.len() != 1 {
                panic!(
                    "Invalid witness length, expected 1 element, watchtower index: {}",
                    watchtower_input.watchtower_idx
                );
            }
            let signature = watchtower_input.watchtower_challenge_witness.0.to_vec()[0].clone();

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
                        watchtower_input.watchtower_idx
                    ),
                }
            } else {
                panic!(
                    "Invalid witness length, expected 64 or 65 bytes, watchtower index: {}",
                    watchtower_input.watchtower_idx
                );
            }
        };

        let sighash = sighash(
            &watchtower_input.watchtower_challenge_tx,
            &prevouts,
            watchtower_input_idx,
            sighash_type,
            watchtower_input.annex_digest,
        );

        if input.previous_output.txid != kickoff_txid {
            panic!(
                "Invalid input: expected input to reference an output from the kickoff transaction (txid: {}), but got txid: {}, vout: {}, watchtower index: {}",
                kickoff_txid,
                input.previous_output.txid,
                input.previous_output.vout,
                watchtower_input.watchtower_idx
            );
        };

        if watchtower_input_idx >= inner_txouts.len() {
            panic!(
                "Invalid watchtower challenge input index, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        }

        let output = inner_txouts[watchtower_input_idx].clone();

        let script_pubkey = output.script_pubkey.clone();

        if !script_pubkey.is_p2tr() {
            panic!(
                "Invalid output script type - kickoff, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        };

        if watchtower_input.watchtower_idx as usize
            >= circuit_input.all_tweaked_watchtower_pubkeys.len()
        {
            panic!(
                "Invalid watchtower index, watchtower index: {}, number of watchtowers: {}",
                watchtower_input.watchtower_idx,
                circuit_input.all_tweaked_watchtower_pubkeys.len()
            );
        }

        let pubkey: [u8; 32] = script_pubkey.as_bytes()[2..34]
            .try_into()
            .expect("Cannot fail");

        if circuit_input.all_tweaked_watchtower_pubkeys[watchtower_input.watchtower_idx as usize]
            != pubkey
        {
            panic!(
                "Invalid watchtower public key, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        }

        let vout = watchtower_input
            .watchtower_idx
            .checked_mul(2)
            .and_then(|x| x.checked_add(circuit_input.watchtower_challenge_connector_start_idx))
            .map(u32::from)
            .expect("Overflow occurred while calculating vout");

        if vout != input.previous_output.vout {
            panic!(
                "Invalid output index, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        }

        let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey) else {
            panic!(
                "Invalid verifying key, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        };

        let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
            panic!(
                "Invalid signature, watchtower index: {}",
                watchtower_input.watchtower_idx
            );
        };

        if verifying_key
            .verify_prehash(sighash.as_byte_array(), &signature)
            .is_ok()
        {
            challenge_sending_watchtowers[(watchtower_input.watchtower_idx as usize) / 8] |=
                1 << (watchtower_input.watchtower_idx % 8);
            watchtower_challenges_outputs
                .push(watchtower_input.watchtower_challenge_tx.output.clone());
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
/// - `kickoff_txid`: The transaction ID of the kickoff transaction.
/// - `circuit_input`: The `BridgeCircuitInput` containing all watchtower inputs and related data.
/// - `work_only_image_id`: A 32-byte identifier used for Groth16 verification against the work-only circuit.
///
/// # Returns
///
/// A tuple containing:
/// - `[u8; 16]`: The total work from the highest valid watchtower challenge (after successful Groth16 verification).
/// - `[u8; 20]`: Bitflags representing which watchtowers sent valid challenges (1 bit per watchtower).
///
/// # Notes
///
/// - The function robustly skips over any challenges that are malformed, have invalid signatures,
///   or do not adhere to the expected transaction output structure.
/// - Each watchtower challenge transaction is expected to contain one of two distinct output structures:
///     - **Single Output Format:** A single `OP_RETURN` script containing a total of 144 bytes.
///       This includes the entire 128-byte compressed Groth16 proof followed by the 16-byte `total_work` value.
///     - **Three Output Format:**
///         - The first two outputs **must** be P2TR (Pay-to-Taproot) outputs. These two outputs
///           collectively contain the first 64 bytes of the compressed Groth16 proof parts
///           (32 bytes from each P2TR output).
///         - The third output **must** be an `OP_RETURN` script, containing the remaining 64 bytes
///           of the compressed Groth16 proof and the 16-byte `total_work` value.
/// - Valid commitments are sorted in descending order by their `total_work` value. The Groth16
///   verifier is then applied sequentially to these sorted commitments, and the first successfully
///   verified `total_work` is selected as the maximum verified work.
pub fn total_work_and_watchtower_flags(
    circuit_input: &BridgeCircuitInput,
    work_only_image_id: &[u8; 32],
) -> (TotalWork, ChallengeSendingWatchtowers) {
    let watchtower_challenge_set = verify_watchtower_challenges(circuit_input);

    let mut valid_watchtower_challenge_commitments: Vec<WatchTowerChallengeTxCommitment> = vec![];

    for outputs in watchtower_challenge_set.challenge_outputs {
        let compressed_g16_proof: [u8; 128];
        let total_work: [u8; 16];

        match outputs.as_slice() {
            // Single OP_RETURN output with 144 bytes
            [op_return_output, ..] if op_return_output.script_pubkey.is_op_return() => {
                // If the first output is OP_RETURN, we expect a single output with 144 bytes
                let Some(Ok(whole_output)) = parse_op_return_data(&outputs[2].script_pubkey)
                    .map(TryInto::<[u8; 144]>::try_into)
                else {
                    continue;
                };
                compressed_g16_proof = whole_output[0..128]
                    .try_into()
                    .expect("Cannot fail: slicing 128 bytes from 144-byte array");
                total_work = borsh::from_slice(&whole_output[128..144])
                    .expect("Cannot fail: deserializing 16 bytes from a 16-byte slice");
            }
            [out1, out2, out3, ..]
                if out1.script_pubkey.is_p2tr()
                    && out2.script_pubkey.is_p2tr()
                    && out3.script_pubkey.is_op_return() =>
            {
                let first_output: [u8; 32] = out1.script_pubkey.to_bytes()[2..]
                    .try_into()
                    .expect("Cannot fail: slicing 32 bytes from P2TR output");
                let second_output: [u8; 32] = out2.script_pubkey.to_bytes()[2..]
                    .try_into()
                    .expect("Cannot fail: slicing 32 bytes from P2TR output");

                let Some(Ok(third_output)) =
                    parse_op_return_data(&out3.script_pubkey).map(TryInto::<[u8; 80]>::try_into)
                else {
                    continue;
                };

                compressed_g16_proof =
                    [&first_output[..], &second_output[..], &third_output[0..64]]
                        .concat()
                        .try_into()
                        .expect("Cannot fail: concatenating and converting to 128-byte array");

                // Borsh deserialization of the final 16 bytes is functionally redundant in this context,
                // as it does not alter the byte content. It is retained here for consistency and defensive safety.
                total_work = borsh::from_slice(&third_output[64..])
                    .expect("Cannot fail: deserializing 16 bytes from 16-byte slice");
            }
            _ => continue,
        }

        let commitment = WatchTowerChallengeTxCommitment {
            compressed_g16_proof,
            total_work,
        };

        valid_watchtower_challenge_commitments.push(commitment);
    }

    valid_watchtower_challenge_commitments.sort_by(|a, b| b.total_work.cmp(&a.total_work));

    let mut total_work_result = [0u8; 16];

    for commitment in valid_watchtower_challenge_commitments {
        if convert_to_groth16_and_verify(
            &commitment.compressed_g16_proof,
            commitment.total_work,
            work_only_image_id,
            circuit_input.hcp.genesis_state_hash,
        ) {
            total_work_result = commitment.total_work;
            break;
        }
    }

    (
        TotalWork(total_work_result),
        ChallengeSendingWatchtowers(watchtower_challenge_set.challenge_senders),
    )
}

pub fn parse_op_return_data(script: &Script) -> Option<&[u8]> {
    let mut instructions = script.instructions();
    if let Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) = instructions.next() {
        if let Some(Ok(Instruction::PushBytes(data))) = instructions.next() {
            return Some(data.as_bytes());
        }
    }
    None
}

/// Computes a deposit constant hash using various transaction and cryptographic components.
///
/// # Parameters
///
/// - `operator_xonlypk`: A 32-byte array representing the operator's X-only public key.
/// - `watchtower_challenge_connector_start_idx`: A 16-bit unsigned integer marking the start index of the watchtower challenge connector.
/// - `watchtower_pubkeys`: A slice of 32-byte arrays representing tweaked watchtower public keys.
/// - `move_txid`: A 32-byte array representing the transaction ID of the move transaction.
/// - `round_txid`: A 32-byte array representing the transaction ID of the round transaction.
/// - `kickoff_round_vout`: A 32-bit unsigned integer indicating the vout of the kickoff round transaction.
///
/// # Returns
///
/// A `DepositConstant` containing a 32-byte SHA-256 hash of the concatenated input components.
pub fn deposit_constant(
    operator_xonlypk: [u8; 32],
    watchtower_challenge_connector_start_idx: u16,
    watchtower_pubkeys: &[[u8; 32]],
    move_txid: [u8; 32],
    round_txid: [u8; 32],
    kickoff_round_vout: u32,
    genesis_state_hash: [u8; 32],
) -> DepositConstant {
    // pubkeys are 32 bytes long
    let pubkey_concat = watchtower_pubkeys
        .iter()
        .flat_map(|pubkey| pubkey.to_vec())
        .collect::<Vec<u8>>();

    let watchtower_pubkeys_digest: [u8; 32] = Sha256::digest(&pubkey_concat).into();

    let pre_deposit_constant = [
        &move_txid,
        &watchtower_pubkeys_digest,
        &operator_xonlypk,
        &watchtower_challenge_connector_start_idx.to_be_bytes()[..],
        &round_txid,
        &kickoff_round_vout.to_be_bytes()[..],
        &genesis_state_hash,
    ]
    .concat();

    DepositConstant(Sha256::digest(&pre_deposit_constant).into())
}

pub fn journal_hash(
    payout_tx_blockhash: PayoutTxBlockhash,
    latest_blockhash: LatestBlockhash,
    challenge_sending_watchtowers: ChallengeSendingWatchtowers,
    deposit_constant: DepositConstant,
) -> blake3::Hash {
    let concatenated_data = [
        payout_tx_blockhash.0,
        latest_blockhash.0,
        challenge_sending_watchtowers.0,
    ]
    .concat();

    let binding = blake3::hash(&concatenated_data);
    let hash_bytes = binding.as_bytes();

    let concat_journal = [deposit_constant.0, *hash_bytes].concat();

    blake3::hash(&concat_journal)
}

/// Computes the Taproot sighash for a given transaction input.
fn sighash(
    wt_tx: &Transaction,
    prevouts: &Prevouts<TxOut>,
    input_index: usize,
    sighash_type: TapSighashType,
    annex_hash: Option<[u8; 32]>,
) -> bitcoin::sighash::TapSighash {
    let mut enc = TapSighash::engine();
    let mut sighash_cache = SighashCache::new(wt_tx);
    taproot_encode_signing_data_to_with_annex_digest::<_, TxOut, &Transaction>(
        sighash_cache.borrow_mut(),
        enc.borrow_mut(),
        input_index,
        prevouts,
        annex_hash,
        None,
        sighash_type,
    );
    TapSighash::from_engine(enc)
}

/// Encodes the BIP341 signing data for any flag type into a given object implementing the
/// [`io::Write`] trait. This version takes a pre-computed annex hash and panics on error.
pub fn taproot_encode_signing_data_to_with_annex_digest<
    W: io::Write + ?Sized,
    T: Borrow<TxOut>,
    R: Borrow<Transaction>,
>(
    sighash_cache: &mut SighashCache<R>,
    writer: &mut W,
    input_index: usize,
    prevouts: &Prevouts<T>,
    annex_hash: Option<[u8; 32]>,
    leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
    sighash_type: TapSighashType,
) {
    let tx = sighash_cache.transaction();
    check_all_prevouts(prevouts, tx);

    let (sighash, anyone_can_pay) = split_anyonecanpay_flag(sighash_type);
    let expect_msg = "writer should not fail";

    // Epoch
    0u8.consensus_encode(writer).expect(expect_msg);

    // Control: hash_type (1).
    (sighash_type as u8)
        .consensus_encode(writer)
        .expect(expect_msg);

    // Transaction Data:
    tx.version.consensus_encode(writer).expect(expect_msg);
    tx.lock_time.consensus_encode(writer).expect(expect_msg);

    if !anyone_can_pay {
        // Manually compute sha_prevouts
        let mut enc_prevouts = sha256::Hash::engine();
        for txin in tx.input.iter() {
            txin.previous_output
                .consensus_encode(&mut enc_prevouts)
                .expect(expect_msg);
        }
        sha256::Hash::from_engine(enc_prevouts)
            .consensus_encode(writer)
            .expect(expect_msg);

        // Manually compute sha_amounts
        let all_prevouts = unwrap_all_prevouts(prevouts);
        let mut enc_amounts = sha256::Hash::engine();
        for prevout in all_prevouts.iter() {
            prevout
                .borrow()
                .value
                .consensus_encode(&mut enc_amounts)
                .expect(expect_msg);
        }
        sha256::Hash::from_engine(enc_amounts)
            .consensus_encode(writer)
            .expect(expect_msg);

        // Manually compute sha_scriptpubkeys
        let mut enc_script_pubkeys = sha256::Hash::engine();
        for prevout in all_prevouts.iter() {
            prevout
                .borrow()
                .script_pubkey
                .consensus_encode(&mut enc_script_pubkeys)
                .expect(expect_msg);
        }
        sha256::Hash::from_engine(enc_script_pubkeys)
            .consensus_encode(writer)
            .expect(expect_msg);

        // Manually compute sha_sequences
        let mut enc_sequences = sha256::Hash::engine();
        for txin in tx.input.iter() {
            txin.sequence
                .consensus_encode(&mut enc_sequences)
                .expect(expect_msg);
        }
        sha256::Hash::from_engine(enc_sequences)
            .consensus_encode(writer)
            .expect(expect_msg);
    }

    if sighash != TapSighashType::None && sighash != TapSighashType::Single {
        // Manually compute sha_outputs
        let mut enc_outputs = sha256::Hash::engine();
        for txout in tx.output.iter() {
            txout.consensus_encode(&mut enc_outputs).expect(expect_msg);
        }
        sha256::Hash::from_engine(enc_outputs)
            .consensus_encode(writer)
            .expect(expect_msg);
    }

    // Data about this input:
    let mut spend_type = 0u8;
    if annex_hash.is_some() {
        spend_type |= 1u8;
    }
    if leaf_hash_code_separator.is_some() {
        spend_type |= 2u8;
    }
    spend_type.consensus_encode(writer).expect(expect_msg);

    if anyone_can_pay {
        let txin = tx.tx_in(input_index).expect("invalid input index");
        let previous_output =
            get_for_prevouts(prevouts, input_index).expect("invalid prevout for input index");
        txin.previous_output
            .consensus_encode(writer)
            .expect(expect_msg);
        previous_output
            .borrow()
            .value
            .consensus_encode(writer)
            .expect(expect_msg);
        previous_output
            .borrow()
            .script_pubkey
            .consensus_encode(writer)
            .expect(expect_msg);
        txin.sequence.consensus_encode(writer).expect(expect_msg);
    } else {
        (input_index as u32)
            .consensus_encode(writer)
            .expect(expect_msg);
    }

    if let Some(hash) = annex_hash {
        hash.consensus_encode(writer).expect(expect_msg);
    }

    // Data about this output:
    if sighash == TapSighashType::Single {
        let mut enc_single_output = sha256::Hash::engine();
        let output = tx
            .output
            .get(input_index)
            .expect("SIGHASH_SINGLE requires a corresponding output");
        output
            .consensus_encode(&mut enc_single_output)
            .expect(expect_msg);
        let hash = sha256::Hash::from_engine(enc_single_output);
        hash.consensus_encode(writer).expect(expect_msg);
    }

    const KEY_VERSION_0: u8 = 0;

    if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
        hash.as_byte_array()
            .consensus_encode(writer)
            .expect(expect_msg);
        KEY_VERSION_0.consensus_encode(writer).expect(expect_msg);
        code_separator_pos
            .consensus_encode(writer)
            .expect(expect_msg);
    }
}

// Helper functions for getting prevouts
fn get_for_prevouts<'a, T: Borrow<TxOut>>(
    prevouts: &'a Prevouts<'a, T>,
    input_index: usize,
) -> Result<&'a T, PrevoutsIndexError> {
    match prevouts {
        Prevouts::One(index, prevout) => {
            if input_index == *index {
                Ok(prevout)
            } else {
                Err(PrevoutsIndexError::InvalidOneIndex)
            }
        }
        Prevouts::All(prevouts) => prevouts
            .get(input_index)
            .ok_or(PrevoutsIndexError::InvalidAllIndex),
    }
}

fn unwrap_all_prevouts<'a, T: Borrow<TxOut>>(prevouts: &'a Prevouts<'a, T>) -> &'a [T] {
    match prevouts {
        Prevouts::All(prevouts) => prevouts,
        _ => panic!("cannot get all prevouts from a single prevout"),
    }
}

fn check_all_prevouts<T: Borrow<TxOut>>(prevouts: &Prevouts<'_, T>, tx: &Transaction) {
    if let Prevouts::All(prevouts) = prevouts {
        if prevouts.len() != tx.input.len() {
            panic!(
                "Invalid number of prevouts: expected {}, got {}",
                tx.input.len(),
                prevouts.len()
            );
        }
    }
}

fn split_anyonecanpay_flag(sighash: TapSighashType) -> (TapSighashType, bool) {
    match sighash {
        TapSighashType::Default => (TapSighashType::Default, false),
        TapSighashType::All => (TapSighashType::All, false),
        TapSighashType::None => (TapSighashType::None, false),
        TapSighashType::Single => (TapSighashType::Single, false),
        TapSighashType::AllPlusAnyoneCanPay => (TapSighashType::All, true),
        TapSighashType::NonePlusAnyoneCanPay => (TapSighashType::None, true),
        TapSighashType::SinglePlusAnyoneCanPay => (TapSighashType::Single, true),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        merkle_tree::BlockInclusionProof,
        spv::SPV,
        structs::{CircuitTxOut, CircuitWitness, WatchtowerInput},
        transaction::CircuitTransaction,
        *,
    };
    use crate::{
        bridge_circuit::structs::{LightClientProof, StorageProof},
        common::constants::{FIRST_FIVE_OUTPUTS, NUMBER_OF_ASSERT_TXS},
        header_chain::{
            mmr_native::MMRInclusionProof, BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader,
        },
    };
    use bitcoin::{
        absolute::Height,
        consensus::{Decodable, Encodable},
        sighash::Annex,
        taproot::TAPROOT_ANNEX_PREFIX,
        transaction::Version,
        Amount, ScriptBuf, Transaction, TxIn, Txid, Witness,
    };
    use lazy_static::lazy_static;
    use risc0_zkvm::compute_image_id;
    use std::io::Cursor;

    const TESTNET4_WORK_ONLY_ELF: &[u8] =
        include_bytes!("../../../risc0-circuits/elfs/testnet4-work-only-guest.bin");

    lazy_static! {
        static ref TESTNET4_WORK_ONLY_IMAGE_ID: [u8; 32] = compute_image_id(TESTNET4_WORK_ONLY_ELF)
            .expect("Elf must be valid")
            .as_bytes()
            .try_into()
            .expect("Elf must be valid");
    }

    fn total_work_and_watchtower_flags_setup() -> (BridgeCircuitInput, Txid) {
        let wt_tx_bytes = include_bytes!("../../test_data/wt_raw_tx.bin");
        let kickoff_raw_tx_bytes = include_bytes!("../../test_data/kickoff_raw_tx.bin");
        let pubkey_hex = "412c00124e48ab8b082a5fa3ee742eb763387ef67adb9f0d5405656ff12ffd50";

        let mut wt_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&wt_tx_bytes)).unwrap();

        let witness = wt_tx.input[0].witness.clone();

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

        let mut watchtower_pubkeys = vec![[0u8; 32]; 160];

        let operator_idx: u16 = 6;

        let pubkey = hex::decode(pubkey_hex).unwrap();

        watchtower_pubkeys[operator_idx as usize] =
            pubkey.try_into().expect("Pubkey must be 32 bytes");

        let watchtower_challenge_connector_start_idx: u16 =
            (FIRST_FIVE_OUTPUTS + NUMBER_OF_ASSERT_TXS) as u16;

        let input = BridgeCircuitInput {
            kickoff_tx: CircuitTransaction(kickoff_tx),
            watchtower_inputs: vec![WatchtowerInput {
                watchtower_idx: operator_idx,
                watchtower_challenge_witness: CircuitWitness(witness),
                watchtower_challenge_input_idx: 0,
                watchtower_challenge_utxos: vec![CircuitTxOut(tx_out)],
                watchtower_challenge_tx: CircuitTransaction(wt_tx.clone()),
                annex_digest: None,
            }],
            hcp: BlockHeaderCircuitOutput {
                method_id: [0; 8],
                genesis_state_hash: [0u8; 32],
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
            all_tweaked_watchtower_pubkeys: watchtower_pubkeys,
            watchtower_challenge_connector_start_idx,
            payout_input_index: 0,
        };

        (input, kickoff_txid)
    }

    #[test]
    fn test_total_work_and_watchtower_flags() {
        let (input, _) = total_work_and_watchtower_flags_setup();

        let (total_work, challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);

        let expected_challenge_sending_watchtowers =
            [64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(*total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            *challenge_sending_watchtowers, expected_challenge_sending_watchtowers,
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    fn test_total_work_and_watchtower_flags_incorrect_witness() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        let mut old_witness = input.watchtower_inputs[0]
            .watchtower_challenge_witness
            .0
            .to_vec()[0]
            .clone();
        old_witness[0] = 0x00;

        let mut new_witness = Witness::new();
        new_witness.push(old_witness);

        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(new_witness);

        let (total_work, challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);

        assert_eq!(*total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            *challenge_sending_watchtowers, [0u8; 20],
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    fn test_total_work_and_watchtower_flags_incorrect_tx() {
        let (mut input, kickoff_txid) = total_work_and_watchtower_flags_setup();

        input.watchtower_inputs[0].watchtower_challenge_tx = CircuitTransaction(Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::from_consensus(0).unwrap()),
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::new(
                    kickoff_txid,
                    input.watchtower_inputs[0].watchtower_challenge_tx.input[0]
                        .previous_output
                        .vout,
                ),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence(0),
                witness: Witness::new(),
            }],
            output: vec![],
        });

        let (total_work, challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);

        assert_eq!(*total_work, [0u8; 16], "Total work is not correct");
        assert_eq!(
            *challenge_sending_watchtowers, [0u8; 20],
            "Challenge sending watchtowers is not correct"
        );
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower challenge input index")]
    fn test_total_work_and_watchtower_flags_tx_in_incorrect_format() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

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
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid witness length")]
    fn test_total_work_and_watchtower_flags_utxo_in_invalid_format() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Create a witness with more than one item, which would be invalid
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0x00]);
        invalid_witness.push([0x01]);
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower public key")]
    fn test_total_work_and_watchtower_flags_invalid_pubkey() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Modify the all_tweaked_watchtower_pubkeys (the array that's actually used in the new code)
        let watch_tower_idx = input.watchtower_inputs[0].watchtower_idx as usize;
        input.all_tweaked_watchtower_pubkeys[watch_tower_idx] = [0u8; 32];

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower challenge input index")]
    fn test_total_work_and_watchtower_flags_invalid_wt_index() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Set an invalid index that's out of bounds
        input.watchtower_inputs[0].watchtower_challenge_input_idx = 160;

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid watchtower challenge input index")]
    fn test_total_work_and_watchtower_flags_invalid_wt_input_index() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Set an input index that's beyond the transaction's inputs
        input.watchtower_inputs[0].watchtower_challenge_input_idx = 10;

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid witness length, expected 64 or 65 bytes")]
    fn test_total_work_and_watchtower_flags_invalid_witness() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Create an invalid witness with 65 bytes but all zeros (signature validation will fail)
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0u8; 63]); // 63 bytes instead of 64/65
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid signature")]
    fn test_total_work_and_watchtower_flags_invalid_witness_2() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Create an invalid witness with 64 bytes but all zeros (signature validation will fail)
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0u8; 64]);
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
    }

    #[test]
    #[should_panic(expected = "Invalid witness length, expected 64 or 65 bytes")]
    fn test_total_work_and_watchtower_flags_invalid_witness_length() {
        let (mut input, _) = total_work_and_watchtower_flags_setup();

        // Create an invalid witness with incorrect length
        let mut invalid_witness = Witness::new();
        invalid_witness.push([0u8; 60]); // Not 64 or 65 bytes
        input.watchtower_inputs[0].watchtower_challenge_witness = CircuitWitness(invalid_witness);

        let (_total_work, _challenge_sending_watchtowers) =
            total_work_and_watchtower_flags(&input, &TESTNET4_WORK_ONLY_IMAGE_ID);
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

    #[test]
    fn test_operator_xonlypk_from_op_return() {
        let payout_tx = include_bytes!("../../../bridge-circuit-host/bin-files/payout_tx.bin");
        let mut payout_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&payout_tx)).unwrap();

        // since this is old payout tx I'll manually change the output. Later replace it with the new one
        let last_output_idx = payout_tx.output.len() - 1;
        payout_tx.output[last_output_idx].script_pubkey = ScriptBuf::from(
            hex::decode("6a204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa")
                .unwrap(),
        );
        let last_output = payout_tx.output.last().unwrap();
        let operator_pk: [u8; 32] = parse_op_return_data(&last_output.script_pubkey)
            .expect("Invalid operator xonlypk")
            .try_into()
            .expect("Invalid xonlypk");

        let expected_pk = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
        assert_eq!(
            hex::encode(operator_pk),
            expected_pk,
            "Operator xonlypk is not correct"
        );
    }

    // Helper function to extract and hash the annex
    fn get_annex_hash(witness: &Witness) -> Option<[u8; 32]> {
        // Using a constant for the annex prefix as defined in bitcoin library

        let watchtower_challenge_annex: Option<Annex> = {
            if let Some(last_witness_element) = witness.last() {
                // Check if the first byte is 0x50 before attempting to create an Annex
                if last_witness_element.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    Annex::new(last_witness_element).ok() // Convert Result<Annex, AnnexError> to Option<Annex>
                } else {
                    None
                }
            } else {
                None
            }
        };

        watchtower_challenge_annex.and_then(|annex| {
            let mut enc = sha256::Hash::engine();
            match annex.consensus_encode(&mut enc) {
                Ok(_) => {
                    let hash = sha256::Hash::from_engine(enc);
                    Some(hash.to_byte_array()) // Use to_byte_array() for owned array
                }
                Err(_) => {
                    // In a production environment, you might want more robust error handling/logging here.
                    // For now, returning None if encoding fails
                    None
                }
            }
        })
    }

    #[test]
    fn test_annex_signature() {
        let bitcoin_tx: Transaction = bitcoin::consensus::deserialize(&hex::decode("020000000001017a48f6958d00c4ab052b0a09589cb0c71df95ec6593fa39aabf3bd130d96da2f8800000000fdffffff010c8602000000000022512065b9b1db7b1d648097913234091a8a7703ca330178efa12437ea97fbc3e14bf2024036f4cd2cf3cf433c9dac8b3205f44ffa4cd8d63f9a6f8191e4fea443ad74c7c50bc8962c2689185f8bb6062ac9ff62b1a8221df45aa377cf3c34566088bff4edfd300250005249464626020000574542505650384c190200002f36800d0097c026008034c8e7fe93810ac4a680d5b004b0ed5a0d3601002699bb3bf659229a10893684426d6cdb50177f0fed1d08d52053a158131a2265fee3ff7f3f059855f202d15da33a5f98ac7a7c07f6342e6d693f826c36ecc857946d392fe8cf906f658025db569cca0b5eec4814e73f5b9a405ef3bd4f44ff27a0fc7cfb215cec477061b71fc00576ec477cfe07d4e7032713ed64e07594ec4c90bd8e27c3bbd13813decd56844e83777335ff183e782a1cc82dce96a553ec4364390801025bb1731df3f135d70f3dfc68b4157c98954f43f45ca92111652bae0361e23476ae1f76ac4844490e1a9e26763e60454098093047ec37ac802f34e6dc5e37f0c57608c44bc28dca0e8e60077889b604b01d6470c653358dedf85d5514e528d0a0390dca4cb841a92795d96c82d203a800aa24a6bd1fbcad272e6ada45d59bcd666d3a4087ea8de6bd1f2b1e5ab0e96165e0f87b9ae0d6a3a2dde02d2b2b680836716fb30910653e3722ad04f73e244159f1b4285aba4b824a49a22ce4f594c50045a2fa26d1b2b294173138d9a0fa264954acc12d5664810d91acb92a03d8b725ee249913c0981515e8db3749772581cc0900d9ce90746fa8ca0d3026882807acf660e92e29ddd3d73cf7c0e664a0d4308043951bc18e09501fb77bba2b09af83e1400e51766c1ccf96b827bc6945388428198bc048f880f01025dbc402bc361c724f8428d824166500a19e88a2b049ac69670604ea010000000000").unwrap()).unwrap();
        let prevout: TxOut = bitcoin::consensus::deserialize(&hex::decode("949902000000000022512065b9b1db7b1d648097913234091a8a7703ca330178efa12437ea97fbc3e14bf2").unwrap()).unwrap();

        let annex_hash = get_annex_hash(&bitcoin_tx.input[0].witness);

        let sighash = sighash(
            &bitcoin_tx,
            &Prevouts::All(&[prevout]),
            0,
            TapSighashType::Default,
            annex_hash, // Pass the computed annex hash
        );

        let xonly_pk_bytes =
            hex::decode("65b9b1db7b1d648097913234091a8a7703ca330178efa12437ea97fbc3e14bf2")
                .unwrap();
        let xonly_pk: VerifyingKey =
            VerifyingKey::from_bytes(&xonly_pk_bytes).expect("Invalid xonly pk");

        // The actual signature is the first element in the witness stack
        let signature_bytes = bitcoin_tx.input[0]
            .witness
            .nth(0)
            .expect("Signature not found in witness")
            .to_vec();

        let signature: Signature =
            Signature::try_from(signature_bytes.as_slice()).expect("Invalid signature");

        xonly_pk
            .verify_prehash(sighash.as_byte_array(), &signature)
            .expect("Signature verification failed");
    }

    #[test]
    #[should_panic(expected = "Signature verification failed")] // This panic is expected if the original signature was created with an annex
    fn test_annex_removed_signature() {
        let mut bitcoin_tx: Transaction = bitcoin::consensus::deserialize(&hex::decode("020000000001017a48f6958d00c4ab052b0a09589cb0c71df95ec6593fa39aabf3bd130d96da2f8800000000fdffffff010c8602000000000022512065b9b1db7b1d648097913234091a8a7703ca330178efa12437ea97fbc3e14bf2024036f4cd2cf3cf433c9dac8b3205f44ffa4cd8d63f9a6f8191e4fea443ad74c7c50bc8962c2689185f8bb6062ac9ff62b1a8221df45aa377cf3c34566088bff4edfd300250005249464626020000574542505650384c190200002f36800d0097c026008034c8e7fe93810ac4a680d5b004b0ed5a0d3601002699bb3bf659229a10893684426d6cdb50177f0fed1d08d52053a158131a2265fee3ff7f3f059855f202d15da33a5f98ac7a7c07f6342e6d693f826c36ecc857946d392fe8cf906f658025db569cca0b5eec4814e73f5b9a405ef3bd4f44ff27a0fc7cfb215cec477061b71fc00576ec477cfe07d4e7032713ed64e07594ec4c90bd8e27c3bbd13813decd56844e83777335ff183e782a1cc82dce96a553ec4364390801025bb1731df3f135d70f3dfc68b4157c98954f43f45ca92111652bae0361e23476ae1f76ac4844490e1a9e26763e60454098093047ec37ac802f34e6dc5e37f0c57608c44bc28dca0e8e60077889b604b01d6470c653358dedf85d5514e528d0a0390dca4cb841a92795d96c82d203a800aa24a6bd1fbcad272e6ada45d59bcd666d3a4087ea8de6bd1f2b1e5ab0e96165e0f87b9ae0d6a3a2dde02d2b2b680836716fb30910653e3722ad04f73e244159f1b4285aba4b824a49a22ce4f594c50045a2fa26d1b2b294173138d9a0fa264954acc12d5664810d91acb92a03d8b725ee249913c0981515e8db3749772581cc0900d9ce90746fa8ca0d3026882807acf660e92e29ddd3d73cf7c0e664a0d4308043951bc18e09501fb77bba2b09af83e1400e51766c1ccf96b827bc6945388428198bc048f880f01025dbc402bc361c724f8428d824166500a19e88a2b049ac69670604ea010000000000").unwrap()).unwrap();
        let prevout: TxOut = bitcoin::consensus::deserialize(&hex::decode("949902000000000022512065b9b1db7b1d648097913234091a8a7703ca330178efa12437ea97fbc3e14bf2").unwrap()).unwrap();

        // Remove the annex from the witness stack
        let signature_bytes = bitcoin_tx.input[0]
            .witness
            .nth(0)
            .expect("Signature not found in witness")
            .to_vec();
        bitcoin_tx.input[0].witness.clear();
        bitcoin_tx.input[0].witness.push(signature_bytes.clone()); // Only push the signature

        // Now, call sighash without providing the annex_hash
        let sighash = sighash(
            &bitcoin_tx,
            &Prevouts::All(&[prevout]),
            0,
            TapSighashType::Default,
            None, // Explicitly pass None for annex_hash
        );

        let xonly_pk_bytes =
            hex::decode("65b9b1db7b1d648097913234091a8a7703ca330178efa12437ea97fbc3e14bf2")
                .unwrap();
        let xonly_pk: VerifyingKey =
            VerifyingKey::from_bytes(&xonly_pk_bytes).expect("Invalid xonly pk");

        let signature: Signature =
            Signature::try_from(signature_bytes.as_slice()).expect("Invalid signature");

        // This verification should fail because the sighash was computed WITHOUT an annex,
        // but the original signature was likely created WITH an annex.
        xonly_pk
            .verify_prehash(sighash.as_byte_array(), &signature)
            .expect("Signature verification failed");
    }

    #[test]
    fn test_parsing_op_return_data_144_bytes() {
        let op_return_data = "6a4c90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let txout = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from(hex::decode(op_return_data).unwrap()),
        };
        assert!(
            txout.script_pubkey.is_op_return(),
            "Script is not OP_RETURN"
        );
        let parsed_data =
            parse_op_return_data(&txout.script_pubkey).expect("Failed to parse OP_RETURN data");
        assert_eq!(parsed_data.len(), 144, "Parsed data length is not correct");
        assert_eq!(parsed_data, [0u8; 144], "Parsed data is not correct");
    }
}
