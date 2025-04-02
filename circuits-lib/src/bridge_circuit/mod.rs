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


    let kickcoff_tx: Transaction = match Decodable::consensus_decode(&mut Cursor::new(&input.kickoff_tx)) {
        Ok(tx) => tx,
        Err(_) => panic!("Invalid kickoff transaction"),
    };

    let kickoff_tx_id = kickcoff_tx.compute_txid();

    let (max_total_work, challenge_sending_watchtowers) = total_work_and_watchtower_flags(
        &kickoff_tx_id,
        &input.watchtower_idxs,
        &input.watchtower_challenge_txs,
        &input.watchtower_challenge_utxos,
        &input.watchtower_challenge_input_idxs,
        &input.watchtower_pubkeys,
        input.num_watchtowers as u32,
        &work_only_image_id,
    );

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

    let deposit_constant =
        deposit_constant(last_output, &kickoff_tx_id, &input.watchtower_pubkeys,input.sp.txid_hex);

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
    kickoff_tx_id: &Txid,
    watchtower_idxs: &[u8],
    watchtower_challenge_txs: &[Vec<u8>],
    watchtower_challenge_utxos: &[Vec<Vec<u8>>],
    watchtower_challenge_input_idxs: &[u8],
    watchtower_pubkeys: &[Vec<u8>],
    num_watchtowers: u32,
    work_only_image_id: &[u8; 32],
) -> ([u8; 16], [u8; 20]) {
    let mut challenge_sending_watchtowers: [u8; 20] = [0u8; 20];
    let mut watchtower_challenges_outputs: Vec<[TxOut; 3]> = vec![];

    // num_watchtowers should be removed, does not make sense to have it
    assert_all_eq!(
        watchtower_challenge_txs.len(),
        watchtower_challenge_utxos.len(),
        watchtower_challenge_input_idxs.len(),
        watchtower_idxs.len(),
        num_watchtowers as usize
    );

    for (_, (((tx, &idx) , utxos), (input_idx))) in watchtower_challenge_txs
        .iter()
        .zip(watchtower_idxs.iter())
        .zip(watchtower_challenge_utxos.iter())
        .zip(watchtower_challenge_input_idxs.iter())
        .enumerate()
    {
        let watchtower_tx: Transaction = match Decodable::consensus_decode(&mut Cursor::new(tx)) {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        let outputs: Vec<TxOut> = match utxos
            .iter()
            .map(|utxo| Decodable::consensus_decode(&mut Cursor::new(utxo)))
            .collect::<Result<_, _>>()
        {
            Ok(outputs) => outputs,
            Err(_) => continue,
        };

        let prevouts = Prevouts::All(&outputs);

        let input = watchtower_tx.input[*input_idx as usize].clone();

        // IS THIS CHECK SHOULD BE HERE?
        if input.previous_output.txid != *kickoff_tx_id {
            continue;
        };

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

        let pubkey = outputs[*input_idx as usize].script_pubkey.clone();

        // IS THIS CHECK CORRECT?
        if !pubkey.is_p2tr() {
            continue;
        };

        // IS THIS CHECK CORRECT?
        if watchtower_pubkeys[idx as usize] != pubkey.as_bytes()[2..34] {
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
            challenge_sending_watchtowers[(idx as usize) / 8 ] |= 1 << (idx % 8);
            if watchtower_tx.output.len() >= 3 {
                watchtower_challenges_outputs.push([
                    watchtower_tx.output[0].clone(),
                    watchtower_tx.output[1].clone(),
                    watchtower_tx.output[2].clone(),
                ]);
            }
        } else {
            continue;
        }
    }

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
        let third_output: [u8; 80] = match parse_op_return_data(&outputs[2].script_pubkey) {
            Some(data) => match data.try_into() {
                Ok(data) => data,
                Err(_) => continue,
            },
            None => continue,
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
    let pre_deposit_constant = [kickoff_tx.to_byte_array(), move_txid_hex, watchtower_pubkeys_digest, operator_id].concat();

    Sha256::digest(&pre_deposit_constant).into()
}

fn sha256_tagged(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha2::Sha256::digest(tag.as_bytes());
    let mut hasher = sha2::Sha256::default();
    sha2::Digest::update(&mut hasher, &tag_hash);
    sha2::Digest::update(&mut hasher, &tag_hash);
    sha2::Digest::update(&mut hasher, msg);
    sha2::Digest::finalize(hasher).try_into().unwrap()
}

fn sighash(
    wt_tx: &Transaction,
    prevouts: &Prevouts<TxOut>,
    input_index: usize,
    sighash_type: TapSighashType,
) -> Result<TapSighash, TaprootError> {
    SighashCache::new(wt_tx).taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
}

// Probably this will not be used in the final implementation but it is useful for debugging purposes, I will keep it here for now
// Only Sighash_Default and Sighash_All are supported
fn sighash_man_implementation(
    wt_tx: &Transaction,
    kickoff_tx: &Transaction,
    hash_type: u8,
) -> [u8; 32] {
    if hash_type > 0x01 {
        panic!("Hash type not supported");
    }
    // Verified
    let hash_prevouts = {
        let mut data = Vec::new();
        for input in &wt_tx.input {
            data.extend(input.previous_output.txid.as_byte_array());
            data.extend(&input.previous_output.vout.to_le_bytes());
        }
        sha2::Sha256::digest(&data).to_vec()
    };

    // Verified
    let hash_amounts = {
        let mut data = Vec::new();
        for input in &wt_tx.input {
            data.extend(
                kickoff_tx.output[input.previous_output.vout as usize]
                    .value
                    .to_sat()
                    .to_le_bytes(),
            );
        }
        sha2::Sha256::digest(&data).to_vec()
    };

    // Verified
    let hash_scriptpubkeys = {
        let mut data = Vec::new();

        for input in &wt_tx.input {
            let size = kickoff_tx.output[input.previous_output.vout as usize]
                .script_pubkey
                .as_bytes()
                .len() as u8;
            data.extend(size.to_le_bytes());
            data.extend(
                kickoff_tx.output[input.previous_output.vout as usize]
                    .script_pubkey
                    .as_bytes(),
            );
        }
        sha2::Sha256::digest(&data).to_vec()
    };

    // Verified
    let hash_sequences = {
        let mut data = Vec::new();
        for input in &wt_tx.input {
            data.extend(input.sequence.0.to_le_bytes());
        }
        sha2::Sha256::digest(&data).to_vec()
    };

    println!("hash sequence {:?}", hex::encode(&hash_sequences));

    // Verified
    let hash_outputs = {
        let mut data = Vec::new();
        for output in &wt_tx.output {
            data.extend(output.value.to_sat().to_le_bytes());
            let size = output.script_pubkey.as_bytes().len() as u8;
            data.extend(size.to_le_bytes());
            data.extend(output.script_pubkey.as_bytes());
        }
        sha2::Sha256::digest(&data).to_vec()
    };

    let epoch: u8 = 0x00;
    let spend_type: u8 = 0x00;
    let input_index = 0u32.to_le_bytes();

    let sig_msg = [
        &[hash_type][..],
        &wt_tx.version.0.to_le_bytes(),
        &wt_tx.lock_time.to_consensus_u32().to_le_bytes(),
        &hash_prevouts,
        &hash_amounts,
        &hash_scriptpubkeys,
        &hash_sequences,
        &hash_outputs,
        &[spend_type],
        &input_index,
    ]
    .concat();

    // Verified
    let message: Vec<u8> = [epoch.to_le_bytes().to_vec(), sig_msg].concat();

    sha256_tagged("TapSighash", &message)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use bitcoin::{
        consensus::{Decodable, Encodable},
        ScriptBuf, Transaction,
    };
    use hex::decode;


    #[test]
    fn test_total_work_and_watchtower_flags() {
        let wt_raw_tx = "03000000000101166a0fe840e9b97954c2de2b47e0a92ef19fc9d41d0ef4aa2c8a1eca55309be23200000000fdffffff044a0100000000000022512000000000000000000000000000000000000000000000000000000000000000004a0100000000000022512000000000000000000000000000000000000000000000000000000000000000000000000000000000536a4c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f0000000000000000451024e730140657306346d184257411f1b125df9a21deb1698d2444e07195e91b894bd49079fcaf002961888417f77b24251f6d899f9972f844d5360e845b6ab69c52272985500000000";
        let kick_off_raw_tx = "030000000001012537bf288fd29577a95773d791c36f8e3592a14f1ba0be680e8c466e7f6bdf1b0300000000fdffffff3c4a01000000000000225120b768ffd7a4bc1db51c279f91dffc13229f81aa3ba5e46c7d07286dc51131fe4ac81900000000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b34a0100000000000022512040b87e69e03b5535637a6fcc3ee4fee978e57944261c06b71c88a47d2d61e1b34a01000000000000225120343d5fec97a99a9d86391ef1ce8773953d3348d24537d96c9d03f3eff01f268a4a01000000000000225120db8ae4a18e31e7f42ef806646f61ab08887ed9883e64126f4d8ccaec84b4baa84a010000000000002251200caecf6b185d67fd85d2b9e094427c0e3ff7da1f2fd6f52f9faebad78b4b10374a01000000000000225120ff6b77430771223e9efd37e88af40ff1e1178c70de6050f4682a9b9b028ffd134a01000000000000225120e5d53a028adf663ce6473e6294778f9959df5608d3e0cb8a5cc7fda020910fc84a01000000000000225120c76db3dcc47e19c17ee5fca221bcde0edc63d36e63f675c2c31abfa11d910be74a0100000000000022512065baa3c3c2b18268cd4b77b2c28d517b97634f762885013c4cfa4f9454bce2884a01000000000000225120df630db048b5f0301b81a139b3b89f57d06e37f8471608b4ef153fe02d1cd2684a01000000000000225120abbd15fb1a93b4a1080921575013312f08917d456a8433fc17767649e199576e4a010000000000002251200d70aff7bf6901911f8eca3447be83b01ee7c21a530c332be9b5563cad77b6b94a01000000000000225120461a8ff1fb58384e80db7386347fddf4442d710b21c045ab8d94598c472757354a01000000000000225120f53b5c6ff7b2ede24f634c326836179261bd03ed17753de3b65214da348d71934a01000000000000225120415a01b25eb2abc681bbaa568cfeb23e7bdb6fd590c5bc3d5edc5aa22b8067654a010000000000002251203be0876038de721f79fab85d536d6c907b70f2093af9daaaf58f56607b39ba394a0100000000000022512075125d48a5b351a61fbcb0eda559089d5e923f9d1d296076e4476c4ce41989134a01000000000000225120fe20b71363e8f4d2c0663df63953ffa81a4d35944cd62af3c5562f503394c1014a01000000000000225120b1dc1c5eedd846370828d2a6a6d79561813e56a826034b02d2fdb1503cd74db94a010000000000002251202b12c204f04c3e8ee75be2e41138de665caab2c8d901b22cdeb26d1adc7a8ef74a0100000000000022512045a1955ba74e8f137e3aa9879a1b1285bf8536bb35884740115e801f477462594a0100000000000022512024a92485b013103d1eed8447acfeb980ab4f49c7d3ca3a8bedd0d4eaa1f39bac4a0100000000000022512069fa0bc89d058279191e57d91bc69a76872a1cb46fc9818e7a220f0ca6351aa24a01000000000000225120b153ace435eca4ba7e9fd2cc2e8d411ba66b939438c177e3e792b1f9d7ae86d14a0100000000000022512002d1f10c622a2bee84df1c18f908e081b2b169b2639e144ad90a5b6146d0d81f4a010000000000002251200455eb49c358d1733f0436800777acba355bf4cb4859eb0809767e5f336c7e344a01000000000000225120edbba5703883af617e41191549dab8db495420e912ce377580c73497d5c006f54a010000000000002251206f996c2d6f9b1c51ec2f0c3514b9a1b1c9aa6abe1662043cc82e89b0e716bd124a01000000000000225120ade73c8862ff85fbd86d4728928d8ddda660dd783130b69eb0e231d3c401940e4a01000000000000225120b597e7f76fe59c1b4d803a887a0b5a8f89ab83550f43c94f63695a1aeacdf1964a010000000000002251200b8b17e3dfbe745d31b9888a00c7832176d4268d62891b423c2a1c7aaf6ac6b24a0100000000000022512058743dd9a0afa61c1550865f4bc1ac292f6900b6fc18bda3b04330707b4644d44a010000000000002251207a69390d336a0f3d2b009b2d77cafd3ebe070629b2eda53fc3fbf8f17c05c6114a01000000000000225120e4db80d3491602afc27ae096f7d2c295a829fcb75bbe25692cb5345544e54bd44a01000000000000225120bc42b39bd556a57cc963ff4a9a655bc9de685c33d13c93b27d922d55e0bd0e9d4a010000000000002251202a3634e30b88744bd163d7a8c7347b9227060cd7f2ca27b7b78ab2017cefa8c84a01000000000000225120e5e170e1cb0e21a1f732efbbf359ab6ad39ad19f2e03cb559126dfa6710b0ede4a010000000000002251206d0d3e2ebcf9984e15fa6f213b606e77b0f9b964c4e21e3de07f4e1d58585ab24a010000000000002251201e87e766e0855030b94d00303bda72c6c1c2f000f6033295db9225a82a6eb1b14a01000000000000225120f6dc65905ff6a26afb918e2a805b4beadad151308909d54838f000cfe7d489554a01000000000000225120bf1e4dec7fdc6aaa45aa32a2515346262928a9120b7f3d27ad4fe2413c9817c34a01000000000000225120b7d6c11354bdaec0e6375d9d67b23f03394f11c3d2f68a0752c802718b855e244a010000000000002251201e133ed484fff1e418e18a9634909fafe006927492ffe29a530f80a0ab49bd714a010000000000002251209e9b06071b1b40e586c61c30708a2b0ee62e28dd96ae484322e36a304c5a7d4e4a010000000000002251204707d11d7396a193afa52fa6afc95307b750e7888020e758f58d127e9468316f4a010000000000002251200ac964d9b6d70fc0f7f4d5bbdfd4b8ee62417be2f65a38d6f5aa689ba52c6cc74a01000000000000225120430617adab19100d55aca58e7e1c631608a1033cb3ddd51028f71c636821f1e34a010000000000002251200c9ce7e513746d9f5f052e770bab93acb34f292e57dfb8f544124b5deb1687054a01000000000000225120ad506c590783a6cee0f1cb4837eae8d76b4963f2dedb7138d117ee87dcc603048403000000000000225120412c00124e48ab8b082a5fa3ee742eb763387ef67adb9f0d5405656ff12ffd504a01000000000000225120472e668be99dc6c4f8de7196e39299c9278bc09d7175c4218dc4796bb4c50ef3840300000000000022512034a23518f12197714e06d865719cf2974e03e9df79cdd641deea57eb3106b33e4a01000000000000225120ab8b54fc2c1b99c18b5e0cb25c08cc58ba12d6ad455ffbeaa1ff9b185902e5388403000000000000225120cb8794c4e1ac6c50abfea8d7b1fef577d8a328e4b0d3c21c3e776835bd43f8444a01000000000000225120f910dfb8dc01fefea6343dfee65d75cccc690714c53a2f919a9350c25029d86c8403000000000000225120e66fd17161ebead62372d2a790cfe0e074f211d3d035f76128ca4f7c73e3af2b4a01000000000000225120df8b413a0f784c06ff832f55b2d26040d847a7470ea54e41875eaae2ecbf35760000000000000000236a214874636dc61fb38c6dfc9681efc4e21e2a5ceb4e7e553dfe32cac45f0f6c06c900f0000000000000000451024e735b40685b8c20a2418c068fd9bb795f36f55b23207c767a625b91d3d896ebb51e9b77cc02d4b27de3ed4de73a8fbfa9f049dc6861d568f2f3027666185d28c6a0dc1c145487cd1ae76f547053f8f8e78e7053fa29a4cfe200144014f263c4e40020b48fd145b18a8500617870360014668b7060b052aaa225ee92d8d045c9df9805623a0014e5829ecde4c40f37efc33fdd6841e0d3d135281800149042af5812ecc89cc47bc7aeb19eb9832ff6aea70014f5a5fbfa6238a02b9d10d2b35e9b72ca132727e50014e3053e90fa1a8382d434a9b3d36d22a0c450a1be00144062dfdcc434d7963dfc52dd93b432a298feacad0014113896e147a433389c80dabf7eedd2d9fbaf66700014fb765ceb94023ced804eb215399b17147ba29e4d0014f8f4fe03cce03e17a1a3967ae15d66399f66364f0014d72c42a0ddad49f4db1216e61042869b5fc6a6e80014458f20d0893dec7814334b1f560d2657619a8b1e001466d7cfce2d44d13cfb1c955406f437dcedb0502c00145596e339065f857d550d5ff588d0c8e4adec1ece001492545c31608cc2586dd2a4403d6b58f145e6b43e00143b5dc73798afcbf8404680efb2b3b0c96465f3bd0014c4a5c4e3c38e6c27ade3be10bc1d7edd56f7952e00145a8ea8c679170d8622f904f47ad363ecfbad547800149f3170001b14bfda7f5cbebed96cac8283d6b94200147869fa25f0804377a6d6f68f8ebc6b9c0e5e9d9f0014fa1cde83c95a573340a810d61502b48bbc4d8a72001486da201760b9aec027b84cac85655909212419b70014a4edaf7b87d7a1bf31441c8a350342be12d3203f00142dc8bafa8c570c939f4e68756ac8dab3f85d5160001462d2bcaafccb0fd7bf595131b0d31fa438ef10a90014502b88bfb9a30f03e74124f83867adf5158f09f10014bf6e2a04e2422c4c9e99e9930c60b123a5ded3630014c245015513cda35e3d78d2c48981d3a3034912a800145596ddb189d6b1e7316fe53cb1875ed8146210bd0014cebb9bb317a91cbd943574a5cbdd9120f86249790014790c5cebafe285198916e3801c7900ba9c88a3340014c110e0cbd37f4bef4bc50f6ab88708ebeb4a59fe0014cf1886a65452c3aa85500f83205768d13909efdd00146628d48d8f38af4b02f369343fdc4b5816077b220014c0268c2d29a1c95832a5aafb4545d308d3e43afc001401c404078546080cd0ef2a3aaf85aaf050da78790014fbfcf334f11839f8516b455d574a38ffe169d4da00146875b0388d0d87132c2250453404ce646c41e61400147a46d1e3ce81d079b39b0f7ca8723fcfca2d107000140d8299da68cda0c90b9031852656dadc6321e5e20014f8897a63a1c205072edbf77f389d3b1b2168fade010214824fad43f7d1ed0036f64d04f0ced6aa373e62bf010514d0510d4a4f883055e04eed67728ba2f4d815187a0108fdd20b5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79147b3145f1863234747bea6d8b4dcf063c7d4a3292886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79140b3ea615bf41fc6950c3bb62b0e85ef3e1765cf3886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79145c177f6101317019b32b2fb99da1cb6a9522a09b886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791413f44b0d87f5304e7fd3a53fa2347a6f0fb81f5b886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79143fc116a7f525d2eb4f48657181e40a9f47d19ef9886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914c642177dcc629db020459874827d2e78b0f5d17a886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914b94dc2ac4426adb37aff3dc9a30f6416855bd8b2886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79144ab94ec9bea648a96b3e8f2e5f963a4f49bafde5886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791451b0f104847cc03ecdedb54a67a643f68357233c886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914d7471964e20c32c47b72d54c178cfa812661b9da886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914ecbbc1cbdb58e815363da2d0b4b2d1e94eaae059886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79147cd9eb0f6d41965c62ac4aa367a5e334cbfb7c11886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914adc0c1391cd26044aa5f4bd61cb938ba9485fd34886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79145b13e70c2b12400fa99ac813582597dca3edb8b4886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791417114f1dfa0a708f840ad1c6ad0310c504fbd33d886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914bd2c3412ffa5a49319b9085b78af826b7706e954886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914deefbc1a4a38415417c1483d299de79a15ec29eb886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914c92a2845833eff59a1a1a7cc2149ed2794c3bb5d886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914869eca4c2fdc40195ea874044562d53ac6f0165b886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914a04a19c6939e575ce975ddd00f807a52251eb343886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914b7e2912917ca22633cd18a7e7a2f36624008dcf3886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79146f1b02def923bab461b50580d31ed354550e6166886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791400da1f01772629920c409e79d6365d9771d095eb886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914d6284d72cb8f009915580924c39ad43970ca5159886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791445b2b58322c96dd708f6034f411e56682ccafe02886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914deb34114412a72b6a263d11e4c351b10085721ed886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79141b4ae97157b019f5cd89f0705d8a9dec8ff6890f886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914efa567e4f49da1681b540d91d241530a6326cab9886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79144da5a33348238e679b05ecd206daedbf3ec7de59886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79143a0d322b55869f9878c8f881934dcbe8a00e1177886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79144d1e2b3d17fbd83076fe0aff918e2ffa14687cc0886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79149ad13004cb19d2bc1a0c2b914105d5da1bd8b326886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791492f7b8bfd865fdb09e230e0e733491451270f9f7886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791499ff2bb1735407ef43964bdab44a0de0d8b228b1886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914be5aec7d04749140fb4dbb00e6901e17f13fdb43886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914704cd11fe1871f3b44aece532a4dd5fcf9918cc2886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791438df16739783a8f021301d11e9e0dcc6773c8434886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914bb66897141b69bd523966b1c3e3e3999fc0cdcd4886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79142f1881a4180bf422591a722b07029b1dda14f59d886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c791470cae3ffaeed345ce4617c68e50aef49717e2e93886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c79143ed17e60f67af28bf11ee31ca18c023cfb966610886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914a8c214d71a7d9a42e8a0e391ea0e82d0f5a02c00886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914418b7f502181e059e878c7a231f3e84171d4049c886d6d6d6d5fa3766b586e9f63756ba9a9a9a9a9a9a9a967946b6876a976a976a976a976a976a976a96c7914a654005c7eb2345e43f60f3f2f47e0807499cdf8886d6d6d6d6c768f6c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d946c7d94025802936c76937693769376936c9376937693769376936c9376937693769376936c93886d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d204f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac41c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de519ee6286ff8e2fc43b18986ba15f311493fc47f4635958e2387a6ed8a7366b30c00000000";

        let raw_tx_bytes = decode(wt_raw_tx).unwrap();
        let wt_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&raw_tx_bytes)).unwrap();

        let kickoff_raw_tx_bytes = decode(kick_off_raw_tx).unwrap();
        let kickoff_tx: Transaction =
            Decodable::consensus_decode(&mut Cursor::new(&kickoff_raw_tx_bytes)).unwrap();

        let output = kickoff_tx.output[wt_tx.input[0].previous_output.vout as usize].clone();

        // READ FROM THE FILE TO PREVENT THE ISSUE WITH ELF - IMAGE ID UPDATE CYCLE
        pub static WORK_ONLY_IMAGE_ID: [u8; 32] =
            hex_literal::hex!("1ff9f5b6d77bbd4296e1749049d4a841088fb72f7a324da71e31fa1576d4bc0b");

        let mut encoded_tx_out = vec![];
        let _ = Encodable::consensus_encode(&output, &mut encoded_tx_out);
        println!("Encoded tx out: {:?}", hex::encode(&encoded_tx_out));

        // let (total_work, challenge_sending_watchtowers) = total_work_and_watchtower_flags(
        //     &[raw_tx_bytes],
        //     &[vec![encoded_tx_out]],
        //     &[0],
        //     1,
        //     &WORK_ONLY_IMAGE_ID,
        // );

        // let mut expected_challenge_sending_watchtowers = [0u8; 20];
        // expected_challenge_sending_watchtowers[0] = 1;
        // assert_eq!(total_work, [0u8; 16], "Total work is not correct");
        // assert_eq!(
        //     challenge_sending_watchtowers, expected_challenge_sending_watchtowers,
        //     "Challenge sending watchtowers is not correct"
        // );
    }

    #[test]
    fn test_parse_op_return_data() {
        let op_return_data = "6a4c500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let script = ScriptBuf::from(hex::decode(op_return_data).unwrap());
        assert!(script.is_op_return(), "Script is not OP_RETURN");
        let parsed_data = parse_op_return_data(&script).expect("Failed to parse OP_RETURN data");
        println!("Parsed data: {:?}", parsed_data);
        assert_eq!(parsed_data, [0u8; 80], "Parsed data is not correct");
    }
}
