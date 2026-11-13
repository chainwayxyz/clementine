// Adapted from chainwayxyz/BitVM aeecbd9ae609aea6651e07adecdd0bc11bfd3adb.
// SP1 binds the program in the Groth16 VK. Its sole variable input is
// mask(BLAKE3(deposit_constant || BLAKE3(payout || latest || watchtowers))).
use bitcoin::Witness;
use bitvm::clementine::utils::{does_raise_error, extend_witness, roll_constant};
use bitvm::treepp::*;
use bitvm::{
    hash::blake3_u4::{blake3_u4_script, bytes_to_nibbles},
    signatures::winternitz::{
        generate_public_key, ListpickVerifier, Parameters, PublicKey, VoidConverter, Winternitz,
    },
};

use bitvm::clementine::utils::does_unlock;

static WINTERNITZ_VERIFIER: Winternitz<ListpickVerifier, VoidConverter> = Winternitz::new();

// ALL the constants need to be divisible by 4
type ChallengeHashType = [u8; 20];
const DEPOSIT_CONSTANT_LEN: usize = 32;
const G16_PUBLIC_INPUT_LEN: usize = 32;
const PAYOUT_TX_BLOCKHASH_LEN: usize = 20;
const LATEST_BLOCKHASH_LEN: usize = 20;
const MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN: usize = 20;
const MAX_WATCHTOWER_COUNT: usize = MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 8;
const NO_ACKNOWLEDGMENT_VALUE: ChallengeHashType = [0u8; 20]; // for not acknowledged preimages, might not be safe
const WINTERNITZ_BLOCK_LEN: u32 = 4;
const BLAKE3_OUTPUT_LEN: u32 = 32; // should be equal to G16_PUBLIC_INPUT_LEN

// If any changes are made to the script generating functions, following 4 constants should also be changed with the values reported from the tests

/// Start of the PAYOUT_TX_BLOCKHASH's checksig's opcodes, precalculated for optimization
const PRECALCULATED_REPLACEMENT_INDEX_0: usize = 18153;
/// Start of the DEPOSIT_CONSTANT's pushing opcodes, precalculated for optimization
const PRECALCULATED_REPLACEMENT_INDEX_1: usize = 92061;

/*
    g16_public_input_verif,
    challenge_sending_watchtowers_verif,
    result_of_watchtower_preimage_checks_on_stack,
    latest_blockhash_verif,
    payout_tx_blockhash_verif,
    hash_check,
*/
const DEBUGGING_POSITIONS: [u32; 6] = [5204, 8600, 14781, 18153, 21485, 163307];
const WITNESS_LENS: [usize; 5] = [86, 86, 160, 86, 134];

/// The Winternitz output reverses the message, and BLAKE3 swaps the nibbles.
/// This script reorders the nibbles of a Winternitz `checksig_verify` output (message) so that it is in the necessary format for BLAKE3.
fn reorder_winternitz_output_for_blake3(len: usize) -> Script {
    script! {
        for i in (0..len).step_by(2).rev() {
            { roll_constant(i) }
            OP_TOALTSTACK
            { roll_constant(i) }
            OP_TOALTSTACK
        }
        for _ in 0..len {
            OP_FROMALTSTACK
        }
    }
}

/// Returns the digits of a Winternitz signature
#[cfg(test)]
fn raw_witness_to_shuffled_digits(signature: Vec<Vec<u8>>) -> Vec<u8> {
    let mut res: Vec<u8> = vec![];
    for i in (0..signature.len()).step_by(2) {
        let digit: u8 = if signature[i + 1].is_empty() {
            0
        } else {
            signature[i + 1][0]
        };
        res.push(digit);
    }
    res
}

/// Reformats the Groth16 public input into Clementine's format
#[cfg(test)]
fn clementine_public_input_reformat(
    mut g16_public_input: [u8; G16_PUBLIC_INPUT_LEN],
) -> [u8; G16_PUBLIC_INPUT_LEN] {
    g16_public_input[0] &= 0x1f;
    for byte in &mut g16_public_input {
        *byte = byte.rotate_left(4);
    }
    g16_public_input
}

/// BLAKE3 in bitVM partitions each byte to 4 bits and puts the more significant ones to the back instead of front
/// To accommodate for this change for any operator_challenge_ack related value, ordering of each 8 consecutive elements are changed
/// i.e. from a_0, a_1, a_2, a_3, a_4, a_5, a_6, a_7, to a_4, a_5, a_6, a_7, a_0, a_1, a_2, a_3
fn change_the_order_of_operator_challenge_acks_according_to_blake3_stack<T>(
    operator_challenge_ack: &mut [T; MAX_WATCHTOWER_COUNT],
) {
    for i in (0..MAX_WATCHTOWER_COUNT).step_by(8) {
        let (first_half, second_half) = operator_challenge_ack.split_at_mut(i + 4);
        first_half[i..i + 4].swap_with_slice(&mut second_half[..4]);
    }
}

/// Given the Winternitz signatures and acknowledgement preimages, reformats the data and reorders the elements to their order in the script
fn get_witness_blocks_with_signatures(
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness,
    challenge_sending_watchtowers_signature: Witness,
    operator_challenge_ack_preimages: Vec<Option<ChallengeHashType>>, // None's are turned into random values
) -> [Witness; 5] {
    let mut operator_challenge_ack_preimages_arr: [Option<ChallengeHashType>;
        MAX_WATCHTOWER_COUNT] = [None; MAX_WATCHTOWER_COUNT];
    operator_challenge_ack_preimages_arr[..operator_challenge_ack_preimages.len()]
        .copy_from_slice(&operator_challenge_ack_preimages);
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(
        &mut operator_challenge_ack_preimages_arr,
    );
    let operator_challenge_ack_preimages_push_values: [ChallengeHashType; MAX_WATCHTOWER_COUNT] =
        operator_challenge_ack_preimages_arr
            .iter()
            .map(|preimage| (*preimage).unwrap_or(NO_ACKNOWLEDGMENT_VALUE))
            .collect::<Vec<_>>()
            .try_into()
            .expect("This should be impossible");

    let mut preimages_witness = Witness::new();
    for preimage in operator_challenge_ack_preimages_push_values {
        preimages_witness.push(preimage);
    }

    [
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        preimages_witness,
        challenge_sending_watchtowers_signature,
        g16_public_input_signature,
    ]
}

/// Given the signatures and acknowledged preimages, returns the witness that will be used to potentially unlock the script
fn get_witness_with_signatures(
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness,
    challenge_sending_watchtowers_signature: Witness,
    operator_challenge_ack_preimages: Vec<Option<ChallengeHashType>>, // None's are turned into random values
) -> Witness {
    let sigs = get_witness_blocks_with_signatures(
        g16_public_input_signature,
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        challenge_sending_watchtowers_signature,
        operator_challenge_ack_preimages,
    );
    let mut w = Witness::new();
    for s in sigs {
        extend_witness(&mut w, s);
    }
    w
}

/// Generates the scripts that is split into 3 chunks from the replacement indices, for more detail: [`create_additional_replacable_disprove_script`]
fn main_script_wrapper(
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
    g16_public_input_pk: PublicKey,
    payout_tx_blockhash_pk: PublicKey,
    latest_blockhash_pk: PublicKey,
    challenge_sending_watchtowers_pk: PublicKey,
    operator_challenge_ack_hashes: Vec<ChallengeHashType>,
) -> (Vec<u8>, usize, usize) {
    assert!(
        operator_challenge_ack_hashes.len() <= MAX_WATCHTOWER_COUNT,
        "Number of Watchtowers is more than allowed"
    );
    let mut operator_challenge_ack_hashes_arr: [ChallengeHashType; MAX_WATCHTOWER_COUNT] =
        [ChallengeHashType::default(); MAX_WATCHTOWER_COUNT];

    operator_challenge_ack_hashes_arr[..operator_challenge_ack_hashes.len()]
        .copy_from_slice(&operator_challenge_ack_hashes);
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(
        &mut operator_challenge_ack_hashes_arr,
    );
    let mut pre_payout_tx_blockhash = script! {
        OP_DEPTH
        { WITNESS_LENS.iter().sum::<usize>() as u32 }
        OP_EQUALVERIFY

        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((G16_PUBLIC_INPUT_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &g16_public_input_pk) }
        { reorder_winternitz_output_for_blake3(G16_PUBLIC_INPUT_LEN * 2) }
        for _ in 0..(G16_PUBLIC_INPUT_LEN * 2) {
            OP_TOALTSTACK
        }
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &challenge_sending_watchtowers_pk) }
        { reorder_winternitz_output_for_blake3(MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) }

        { 0 } // If all of the hashes are valid, this should stay as zero
        OP_TOALTSTACK

        for (i, chunk) in operator_challenge_ack_hashes_arr.chunks(4).enumerate().rev() {
            OP_DUP OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            for b in (0..4).rev() {
                if b != 0 {
                    { 1 << b } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB
                        { 0 }
                    OP_ELSE
                        OP_DROP
                        { 1 }
                    OP_ENDIF
                    { roll_constant(i + 2) }
                } else {
                    //Number is the result
                    OP_NOT // Range shouldn't be an issue due to winternitz bound checks
                    { roll_constant(i + 1) }
                }
                OP_HASH160
                { chunk[b].to_vec() }
                OP_EQUAL
                OP_BOOLAND
                OP_FROMALTSTACK
                OP_BOOLOR
                OP_TOALTSTACK
            }
        }

        // {payout_tx_blockhash_signature, latest_blockhash_signature}  {g16_public_input, challenge_sending_watctowers, result_of_the_preimage_check(bool)}
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((LATEST_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &latest_blockhash_pk) }
        { reorder_winternitz_output_for_blake3(LATEST_BLOCKHASH_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
            OP_TOALTSTACK
        }
    }.compile().to_bytes();

    let pre_deposit_constant = script! {
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((PAYOUT_TX_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &payout_tx_blockhash_pk) } // This will be replaced
        { reorder_winternitz_output_for_blake3(PAYOUT_TX_BLOCKHASH_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
            OP_FROMALTSTACK
        }
        OP_FROMALTSTACK // preimage check result
        for _ in 0..(MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) {
            OP_FROMALTSTACK
        }
        { roll_constant(MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) } //send preimage result to the back
        OP_TOALTSTACK
        { blake3_u4_script((PAYOUT_TX_BLOCKHASH_LEN + LATEST_BLOCKHASH_LEN + MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN) as u32) }
        for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
            OP_TOALTSTACK
        }
    }.compile().to_bytes();

    let rest_of_the_script = script! {
        for x in bytes_to_nibbles(deposit_constant.to_vec()) {
            { x }
        }
        for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
            OP_FROMALTSTACK
        }
        { blake3_u4_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
        { mask_sp1_digest() }

        OP_FROMALTSTACK // preimage check result
        for i in 0..(G16_PUBLIC_INPUT_LEN * 2) {
            OP_FROMALTSTACK
            if i % 2 == 1 {
                OP_SWAP //BitVM corruption
            }
        }

        { roll_constant(G16_PUBLIC_INPUT_LEN * 2) } //send preimage result to the back
        OP_TOALTSTACK

        for i in (0..(G16_PUBLIC_INPUT_LEN * 2)).rev() {
            { roll_constant(i + 1) }
            OP_NUMNOTEQUAL // Both in range, so should be fine
            OP_FROMALTSTACK
            OP_BOOLOR
            OP_TOALTSTACK
        }

        OP_FROMALTSTACK
    }
    .compile()
    .to_bytes();
    let replacement_0 = pre_payout_tx_blockhash.len();
    let replacement_1 = replacement_0 + pre_deposit_constant.len();
    pre_payout_tx_blockhash.extend(pre_deposit_constant);
    pre_payout_tx_blockhash.extend(rest_of_the_script);
    (pre_payout_tx_blockhash, replacement_0, replacement_1)
}

/// Generates the additional disprove script using given parameters.
///
/// Given the provided constants, public keys, and acknowledgment hashes, this script evaluates three conditions:
///
/// 1. **Signature Verification:**
///    Ensures that all given signatures (provided in the unlocking script - witness)
///    match the corresponding public keys passed as function arguments.
///
/// 2. **Hash Equality Check:**
///    Verifies whether the signed values satisfy the following equality constraint
///    (expressed using an auxiliary variable for clarity):
///
///    - `X = BLAKE3(payout_tx_blockhash, latest_blockhash, challenge_sending_watchtowers)`
///    - `groth16_public_input = BLAKE3(deposit_constant, X)` with the high three bits cleared
///      (253 bits retained). This is SP1's digest of the bridge public values
///      `deposit_constant || X`.
///
/// 3. **Compliance of Acknowledged Preimages and `challenge_sending_watchtowers` Check:**
///    Ensures that there exists at least one watchtower such that:
///    - Its acknowledgment bit is set to zero.
///    - The given preimage in the unlocking script (witness), when hashed using `OP_HASH160`, matches the watchtower's expected hash.
///
///    The script is spendable if **condition 1 is satisfied** and **at least one of conditions 2 or 3 is not met**, meaning the spending condition is:
///
///    `Signature Verification AND NOT (Hash Equality Check AND Compliance of Acknowledged Preimages and challenge_sending_watchtowers Check)`
///
///    To successfully unlock, the script expects a witness in the following format:
///
///    ```text
///    [
///      payout_tx_blockhash_signature,
///      latest_blockhash_signature,
///      `WATCHTOWER_COUNT` preimages (in the corrected format) (if a preimage is not revealed, a dummy value can be used instead),
///      challenge_sending_watchtowers_signature,
///      g16_public_input_signature
///    ]
///    ```
///
///     The `payout_tx_blockhash_pk` and `deposit_constant` can be replaced with other values, using the function `replace_placeholders_in_script`
///
/// ## Arguments
///
/// * `deposit_constant` - Deposit Constant, in bytes, this constant is later replaceable by other functions
/// * `g16_public_input_pk` - Winternitz Public key for Groth16 Public Input used in BitVM
/// * `payout_tx_blockhash_pk` - Winternitz Public key for Payout Transaction Blockhash, this public key is later replaceable by other functions
/// * `latest_blockhash_pk` - Winternitz Public key for Latest Blockhash
/// * `challenge_sending_watchtowers_pk` - Winternitz Public key for the array of challenge sending watchtowers; in this array, watchtowers are numerated in the order of the numbers and their least significant bit
///   (Even if the number of watchtowers is less than 160, this public key should be for a 20 byte array, and 0's should be used for non existent ones)
/// * `operator_challenge_ack_hashes` - Operator's acknowledgement hashes for each watchtower, i.e. result of OP_HASH160'd preimages
///
/// ## Returns
///
/// * `Vec<u8>` - The compiled Bitcoin script as a byte vector.
///
/// ## Notes
///
/// - Checking the number of arguments might be necessary, in order to block malicious attempts
/// - To use 'wots_api.rs' public keys, it is enough to cast them to vectors
pub fn create_additional_replacable_disprove_script(
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
    g16_public_input_pk: PublicKey,
    payout_tx_blockhash_pk: PublicKey,
    latest_blockhash_pk: PublicKey,
    challenge_sending_watchtowers_pk: PublicKey,
    operator_challenge_ack_hashes: Vec<ChallengeHashType>,
) -> Vec<u8> {
    let (res, _, _) = main_script_wrapper(
        deposit_constant,
        g16_public_input_pk,
        payout_tx_blockhash_pk,
        latest_blockhash_pk,
        challenge_sending_watchtowers_pk,
        operator_challenge_ack_hashes,
    );
    res
}

/// Same as `create_additional_replacable_disprove_script`, but creates the script without expecting `payout_tx_blockhash_pk' and `deposit_constant` as an argument, with dummy elements
pub fn create_additional_replacable_disprove_script_with_dummy(
    /* deposit_constant: [u8; DEPOSIT_CONSTANT_LEN], */
    g16_public_input_pk: PublicKey,
    /* payout_tx_blockhash_pk: PublicKey, */
    latest_blockhash_pk: PublicKey,
    challenge_sending_watchtowers_pk: PublicKey,
    operator_challenge_ack_hashes: Vec<ChallengeHashType>,
) -> Vec<u8> {
    create_additional_replacable_disprove_script(
        [0u8; DEPOSIT_CONSTANT_LEN],
        g16_public_input_pk,
        generate_public_key(
            &Parameters::new_by_bit_length(PAYOUT_TX_BLOCKHASH_LEN as u32 * 8, 4),
            &vec![0u8; 0],
        ),
        latest_blockhash_pk,
        challenge_sending_watchtowers_pk,
        operator_challenge_ack_hashes,
    )
}

/// Returns the unlocking witness from given parameters for the given additional disprove script
///
/// This function constructs a witness from the provided signatures and preimages. \
/// Checks if the given parameters are make the given compiled additional disprove script spendable
/// If so, returns the witness that unlocks the script
///
/// ## Arguments
///
/// * `replacable_script` - The compiled additional script verifies the conditions for spending.
/// * `g16_public_input_signature` - The witness signature for the Groth16 Public Input.
/// * `payout_tx_blockhash_signature` - The witness signature for the Payout Transaction Blockhash.
/// * `latest_blockhash_signature` - The witness signature for the Latest Blockhash.
/// * `challenge_sending_watchtowers_signature` - The witness signature for challenge sending watchtowers; in this array, watchtowers are numerated in the order of the numbers and their least significant bit
/// * `operator_challenge_ack_preimages` - An array of optional (given if it is revealed) challenge acknowledgment preimages from watchtowers. If `None`, a random value is substituted.
///
/// ## Returns
///
/// * `Some(Witness)` - If given parameters unlock the additional script
/// * `None` - If not
///
/// ## Notes
///
/// - To use `wots_api.rs` signatures, use the function wotsxxx.`signature_to_raw_witness`
pub fn validate_assertions_for_additional_script(
    replacable_script: Vec<u8>,
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness,
    challenge_sending_watchtowers_signature: Witness,
    operator_challenge_ack_preimages: Vec<Option<ChallengeHashType>>, // None's are turned into random values
) -> Option<Witness> {
    assert!(
        operator_challenge_ack_preimages.len() <= MAX_WATCHTOWER_COUNT,
        "Number of Watchtowers is more than allowed"
    );
    let w = get_witness_with_signatures(
        g16_public_input_signature,
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        challenge_sending_watchtowers_signature,
        operator_challenge_ack_preimages,
    );
    if does_unlock(replacable_script, w.to_vec()) {
        Some(w)
    } else {
        None
    }
}

/// Returns (payout_tx_blockhash_signature, latest_blockhash_signature, witness_preimages, challenge_sending_watchtowers_signature, g16_public_input_signature)
pub fn split_additional_disprove_witness(
    w: Witness,
) -> (
    Witness,
    Witness,
    [Vec<u8>; MAX_WATCHTOWER_COUNT],
    Witness,
    Witness,
) {
    let v = w.to_vec();
    let mut pref = [0usize; 5];
    for i in 1..5 {
        pref[i] = pref[i - 1] + WITNESS_LENS[i - 1];
    }
    assert_eq!(v.len(), pref[4] + WITNESS_LENS[4]);
    let mut payout_tx_blockhash_signature = Witness::new();
    let mut latest_blockhash_signature = Witness::new();
    //let mut preimages: [Vec<u8>; MAX_WATCHTOWER_COUNT] = from_fn(|_| Vec::new());
    let mut challenge_sending_watchtowers_signature = Witness::new();
    let mut g16_public_input_signature = Witness::new();

    for i in 0..WITNESS_LENS[0] {
        payout_tx_blockhash_signature.push(v[pref[0] + i].clone());
    }
    for i in 0..WITNESS_LENS[1] {
        latest_blockhash_signature.push(v[pref[1] + i].clone());
    }

    let mut preimages = v[pref[2]..pref[3]].to_vec().try_into().expect("Impossible");

    for i in 0..WITNESS_LENS[3] {
        challenge_sending_watchtowers_signature.push(v[pref[3] + i].clone());
    }
    for i in 0..WITNESS_LENS[4] {
        g16_public_input_signature.push(v[pref[4] + i].clone());
    }

    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(&mut preimages); //this operations inverse is itself, so it works
    (
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        preimages,
        challenge_sending_watchtowers_signature,
        g16_public_input_signature,
    )
}

/// Replaces the payout transaction blockhash public key and deposit constant for the given script
///
/// This function modifies the provided script by replacing the `checksig_verify` of the Payout Transaction Blockhash
///
/// ## Arguments
///
/// * `replacable_script` - Compiled additional disprove script
/// * `payout_tx_blockhash_pk` - The replacement public key for payout transaction blockhash
/// * `deposit_constant` - The replacement deposit constant
///
/// ## Returns
///
/// * `Vec<u8>` - The modified script with the updated payout transaction blockhash verification
///
/// ## Note
/// - To use `wots_api.rs` public keys, cast them to vectors
pub fn replace_placeholders_in_script(
    mut replacable_script: Vec<u8>,
    payout_tx_blockhash_pk: PublicKey,
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
) -> Vec<u8> {
    let payout_tx_replacement = WINTERNITZ_VERIFIER
        .checksig_verify(
            &Parameters::new_by_bit_length(
                (PAYOUT_TX_BLOCKHASH_LEN * 8) as u32,
                WINTERNITZ_BLOCK_LEN,
            ),
            &payout_tx_blockhash_pk,
        )
        .compile()
        .to_bytes();
    let deposit_constant_replacement = script! {
        for x in bytes_to_nibbles(deposit_constant.to_vec()) {
            { x }
        }
    }
    .compile()
    .to_bytes();
    replacable_script[PRECALCULATED_REPLACEMENT_INDEX_0
        ..PRECALCULATED_REPLACEMENT_INDEX_0 + payout_tx_replacement.len()]
        .copy_from_slice(&payout_tx_replacement);
    replacable_script[PRECALCULATED_REPLACEMENT_INDEX_1
        ..PRECALCULATED_REPLACEMENT_INDEX_1 + deposit_constant_replacement.len()]
        .copy_from_slice(&deposit_constant_replacement);
    replacable_script
}

/// This function (likewise [`debug_assertions_for_additional_script`]) is not stable,
/// and would probably break if any substantial script change is done, since some part is copy pasted from the main script \
/// (writing it otherwise would complicate the actual code a bit more)
#[cfg(test)]
fn find_script_debugging_positions(
    deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
    g16_public_input_pk: PublicKey,
    payout_tx_blockhash_pk: PublicKey,
    latest_blockhash_pk: PublicKey,
    challenge_sending_watchtowers_pk: PublicKey,
    operator_challenge_ack_hashes: Vec<ChallengeHashType>,
) -> Vec<u32> {
    assert!(
        operator_challenge_ack_hashes.len() <= MAX_WATCHTOWER_COUNT,
        "Number of Watchtowers is more than allowed"
    );
    let mut operator_challenge_ack_hashes_arr: [ChallengeHashType; MAX_WATCHTOWER_COUNT] =
        [ChallengeHashType::default(); MAX_WATCHTOWER_COUNT];

    operator_challenge_ack_hashes_arr[..operator_challenge_ack_hashes.len()]
        .copy_from_slice(&operator_challenge_ack_hashes);
    change_the_order_of_operator_challenge_acks_according_to_blake3_stack(
        &mut operator_challenge_ack_hashes_arr,
    );

    let g16_public_input_verif = script! {
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((G16_PUBLIC_INPUT_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &g16_public_input_pk) }
        { reorder_winternitz_output_for_blake3(G16_PUBLIC_INPUT_LEN * 2) }
    }.compile().to_bytes().len();

    let challenge_sending_watchtowers_verif = script! {
        for _ in 0..(G16_PUBLIC_INPUT_LEN * 2) {
            OP_TOALTSTACK
        }
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &challenge_sending_watchtowers_pk) }
        { reorder_winternitz_output_for_blake3(MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) }
    }.compile().to_bytes().len();

    let result_of_watchtower_preimage_checks_on_stack = script! {
        OP_DEPTH
        { WITNESS_LENS.iter().sum::<usize>() as u32 }
        OP_EQUALVERIFY

        { 0 } // If all of the hashes are valid, this should stay as zero
        OP_TOALTSTACK

        for (i, chunk) in operator_challenge_ack_hashes_arr.chunks(4).enumerate().rev() {
            OP_DUP OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            for b in (0..4).rev() {
                if b != 0 {
                    { 1 << b } OP_2DUP
                    OP_GREATERTHANOREQUAL
                    OP_IF
                        OP_SUB
                        { 0 }
                    OP_ELSE
                        OP_DROP
                        { 1 }
                    OP_ENDIF
                    { roll_constant(i + 2) }
                } else {
                    //Number is the result
                    OP_NOT // Range shouldn't be an issue due to winternitz bound checks
                    { roll_constant(i + 1) }
                }
                OP_HASH160
                { chunk[b].to_vec() }
                OP_EQUAL
                OP_BOOLAND
                OP_FROMALTSTACK
                OP_BOOLOR
                OP_TOALTSTACK
            }
        }
    }
    .compile()
    .to_bytes()
    .len();

    let latest_blockhash_verif = script! {
        // {payout_tx_blockhash_signature, latest_blockhash_signature}  {g16_public_input, challenge_sending_watctowers, result_of_the_preimage_check(bool)}
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((LATEST_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &latest_blockhash_pk) }
        { reorder_winternitz_output_for_blake3(LATEST_BLOCKHASH_LEN * 2) } //Winternitz reverses the message

        for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
            OP_TOALTSTACK
        }
    }.compile().to_bytes().len();

    let payout_tx_blockhash_verif = script! {
        { WINTERNITZ_VERIFIER.checksig_verify(&Parameters::new_by_bit_length((PAYOUT_TX_BLOCKHASH_LEN * 8) as u32, WINTERNITZ_BLOCK_LEN), &payout_tx_blockhash_pk) } // This will be replaced
        { reorder_winternitz_output_for_blake3(PAYOUT_TX_BLOCKHASH_LEN * 2) }
    }
    .compile()
    .to_bytes()
    .len();

    let hash_check = script! { //this shouldn't be necessary since its the only remaining possibility

        for _ in 0..(LATEST_BLOCKHASH_LEN * 2) {
            OP_FROMALTSTACK
        }
        OP_FROMALTSTACK // preimage check result
        for _ in 0..(MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) {
            OP_FROMALTSTACK
        }
        { roll_constant(MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 2) } //send preimage result to the back
        OP_TOALTSTACK
        { blake3_u4_script((PAYOUT_TX_BLOCKHASH_LEN + LATEST_BLOCKHASH_LEN + MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN) as u32) }
        for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
            OP_TOALTSTACK
        }
        for x in bytes_to_nibbles(deposit_constant.to_vec()) {
            { x }
        }
        for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
            OP_FROMALTSTACK
        }
        { blake3_u4_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
        { mask_sp1_digest() }

        OP_FROMALTSTACK // preimage check result
        for i in 0..(G16_PUBLIC_INPUT_LEN * 2) {
            OP_FROMALTSTACK
            if i % 2 == 1 {
                OP_SWAP //BitVM corruption
            }
        }

        { roll_constant(G16_PUBLIC_INPUT_LEN * 2) } //send preimage result to the back
        OP_TOALTSTACK

        for i in (0..(G16_PUBLIC_INPUT_LEN * 2)).rev() {
            { roll_constant(i + 1) }
            OP_NUMNOTEQUAL // Both in range, so should be fine
            OP_FROMALTSTACK
            OP_BOOLOR
            OP_TOALTSTACK
        }

        OP_FROMALTSTACK
    }.compile().to_bytes().len();
    let v = [
        g16_public_input_verif,
        challenge_sending_watchtowers_verif,
        result_of_watchtower_preimage_checks_on_stack,
        latest_blockhash_verif,
        payout_tx_blockhash_verif,
        hash_check,
    ];
    let mut pref: Vec<u32> = vec![0; v.len()];
    pref[0] = v[0] as u32;
    for i in 1..v.len() {
        pref[i] = pref[i - 1] + v[i] as u32;
    }

    assert_eq!(
        pref[v.len() - 1],
        main_script_wrapper(
            deposit_constant,
            g16_public_input_pk,
            payout_tx_blockhash_pk,
            latest_blockhash_pk,
            challenge_sending_watchtowers_pk,
            operator_challenge_ack_hashes
        )
        .0
        .len() as u32,
        "This probably indicates that script has changed and debugging doesn't work anymore, you need to patch this function inorder for it to work"
    );
    pref
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdditionalDisproveDebugError {
    G16PublicInputChecksig,              //if checksig fails
    ChallengeSendingWatchtowersChecksig, //if checksig fails
    WatchtowerPreimageCheck,             //if acknowledged and preimages are not congruent
    LatestBlockhashChecksig,             //if checksig fails
    PayoutTxBlockhashChecksig,           //if checksig fails
    Blake3HashCheck,                     //if hash != public_input (NOT EQUAL)
}

/// Returns the first applicable debugging condition, in the order of the enum [`AdditionalDisproveDebugError`]
/// Should be used with caution if any substantial change is done to the main script
pub fn debug_assertions_for_additional_script(
    replacable_script: Vec<u8>,
    g16_public_input_signature: Witness,
    payout_tx_blockhash_signature: Witness,
    latest_blockhash_signature: Witness,
    challenge_sending_watchtowers_signature: Witness,
    operator_challenge_ack_preimages: Vec<Option<ChallengeHashType>>, // None's are turned into random values
) -> Option<AdditionalDisproveDebugError> {
    assert!(
        operator_challenge_ack_preimages.len() <= MAX_WATCHTOWER_COUNT,
        "Number of Watchtowers is more than allowed"
    );
    let w = get_witness_with_signatures(
        g16_public_input_signature,
        payout_tx_blockhash_signature,
        latest_blockhash_signature,
        challenge_sending_watchtowers_signature,
        operator_challenge_ack_preimages,
    );
    if does_raise_error(
        replacable_script.clone()[..DEBUGGING_POSITIONS[0] as usize].to_vec(),
        w.to_vec(),
    ) {
        Some(AdditionalDisproveDebugError::G16PublicInputChecksig)
    } else if does_raise_error(
        replacable_script.clone()[..DEBUGGING_POSITIONS[1] as usize].to_vec(),
        w.to_vec(),
    ) {
        Some(AdditionalDisproveDebugError::ChallengeSendingWatchtowersChecksig)
    } else {
        let mut script = replacable_script.clone()[..DEBUGGING_POSITIONS[2] as usize].to_vec();
        script.extend(
            script! {
                OP_FROMALTSTACK
                OP_0
                OP_EQUALVERIFY
            }
            .compile()
            .to_bytes(),
        );
        if does_raise_error(script, w.to_vec()) {
            Some(AdditionalDisproveDebugError::WatchtowerPreimageCheck)
        } else if does_raise_error(
            replacable_script.clone()[..DEBUGGING_POSITIONS[3] as usize].to_vec(),
            w.to_vec(),
        ) {
            Some(AdditionalDisproveDebugError::LatestBlockhashChecksig)
        } else if does_raise_error(
            replacable_script.clone()[..DEBUGGING_POSITIONS[4] as usize].to_vec(),
            w.to_vec(),
        ) {
            Some(AdditionalDisproveDebugError::PayoutTxBlockhashChecksig)
        } else if does_unlock(replacable_script, w.to_vec()) {
            Some(AdditionalDisproveDebugError::Blake3HashCheck)
        } else {
            None
        }
    }
}

/// Preserve all 253 bits of the SP1 digest. Stack order is byte order, high nibble first.
fn mask_sp1_digest() -> Script {
    script! {
        for _ in 0..63 { OP_TOALTSTACK }
        OP_DUP 8 OP_GREATERTHANOREQUAL OP_IF 8 OP_SUB OP_ENDIF
        OP_DUP 4 OP_GREATERTHANOREQUAL OP_IF 4 OP_SUB OP_ENDIF
        OP_DUP 2 OP_GREATERTHANOREQUAL OP_IF 2 OP_SUB OP_ENDIF
        for _ in 0..63 { OP_FROMALTSTACK }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{hash160, Hash};
    use bitvm::{hash::blake3_u4::blake3_bitvm_version, signatures::winternitz::SecretKey};
    use rand::{thread_rng, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    const WINTERNITZ_SECRET_KEY_LEN: usize = 40;

    /// Given the secret keys and the values of the variables, generates the signature witnesses for each one
    #[allow(clippy::too_many_arguments)]
    fn get_signatures(
        g16_public_input: [u8; G16_PUBLIC_INPUT_LEN],
        payout_tx_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN],
        latest_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN],
        challenge_sending_watchtowers: [u8; MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN],
        g16_public_input_sk: SecretKey,
        payout_tx_blockhash_sk: SecretKey,
        latest_blockhash_sk: SecretKey,
        challenge_sending_watchtowers_sk: SecretKey,
    ) -> [Witness; 4] {
        [
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (G16_PUBLIC_INPUT_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &g16_public_input_sk,
                clementine_public_input_reformat(g16_public_input).as_ref(),
            ),
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (PAYOUT_TX_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &payout_tx_blockhash_sk,
                payout_tx_blockhash.as_ref(),
            ),
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (LATEST_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &latest_blockhash_sk,
                latest_blockhash.as_ref(),
            ),
            WINTERNITZ_VERIFIER.sign(
                &Parameters::new_by_bit_length(
                    (MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &challenge_sending_watchtowers_sk,
                challenge_sending_watchtowers.as_ref(),
            ),
        ]
    }

    fn generate_winternitz_secret_key() -> SecretKey {
        let mut rng = thread_rng();
        (0..WINTERNITZ_SECRET_KEY_LEN).map(|_| rng.gen()).collect()
    }

    fn concat_all<T: Clone>(lists: &[&[T]]) -> Vec<T> {
        lists.iter().flat_map(|list| list.iter().cloned()).collect()
    }

    /// This function changes with the `create_additional_replacable_disprove_script` and calculates the starting index of replacements
    fn calculate_additional_replacable_disprove_script_replacement_indices(
        deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
        g16_public_input_pk: PublicKey,
        payout_tx_blockhash_pk: PublicKey,
        latest_blockhash_pk: PublicKey,
        challenge_sending_watchtowers_pk: PublicKey,
        operator_challenge_ack_hashes: Vec<ChallengeHashType>,
    ) -> (usize, usize) {
        let (_, replacement_0, replacement_1) = main_script_wrapper(
            deposit_constant,
            g16_public_input_pk,
            payout_tx_blockhash_pk,
            latest_blockhash_pk,
            challenge_sending_watchtowers_pk,
            operator_challenge_ack_hashes,
        );
        (replacement_0, replacement_1)
    }

    #[derive(Debug)]
    struct SignerData {
        deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
        g16_public_input: [u8; G16_PUBLIC_INPUT_LEN],
        payout_tx_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN],
        latest_blockhash: [u8; PAYOUT_TX_BLOCKHASH_LEN],
        challenge_sending_watchtowers: [u8; MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN],
        operator_challenge_ack_preimages: Vec<ChallengeHashType>,
        g16_public_input_sk: SecretKey,
        payout_tx_blockhash_sk: SecretKey,
        latest_blockhash_sk: SecretKey,
        challenge_sending_watchtowers_sk: SecretKey,
    }
    struct PublicData {
        deposit_constant: [u8; DEPOSIT_CONSTANT_LEN],
        g16_public_input_pk: PublicKey,
        payout_tx_blockhash_pk: PublicKey,
        latest_blockhash_pk: PublicKey,
        challenge_sending_watchtowers_pk: PublicKey,
        operator_challenge_ack_hashes: Vec<ChallengeHashType>,
    }

    fn random_signer_data(seed: u64) -> SignerData {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut s = SignerData {
            deposit_constant: rng.gen::<[u8; DEPOSIT_CONSTANT_LEN]>(),
            g16_public_input: [0; G16_PUBLIC_INPUT_LEN], //calculate later
            payout_tx_blockhash: rng.gen::<[u8; PAYOUT_TX_BLOCKHASH_LEN]>(),
            latest_blockhash: rng.gen::<[u8; PAYOUT_TX_BLOCKHASH_LEN]>(),
            challenge_sending_watchtowers: rng.gen::<[u8; MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN]>(), // Exceeding bits can be one, there is no problem
            operator_challenge_ack_preimages: (0..rng.gen_range(1..=MAX_WATCHTOWER_COUNT))
                .map(|_| rng.gen::<ChallengeHashType>())
                .collect(),
            g16_public_input_sk: generate_winternitz_secret_key(),
            payout_tx_blockhash_sk: generate_winternitz_secret_key(),
            latest_blockhash_sk: generate_winternitz_secret_key(),
            challenge_sending_watchtowers_sk: generate_winternitz_secret_key(),
        };
        let x = blake3_bitvm_version(concat_all(&[
            &s.payout_tx_blockhash,
            &s.latest_blockhash,
            &s.challenge_sending_watchtowers,
        ]));
        let mut f = blake3_bitvm_version(concat_all(&[&s.deposit_constant, &x]));
        f[0] &= 0x1f;
        s.g16_public_input = f;
        s
    }

    fn get_public_data_from_signer(signer_data: &SignerData) -> PublicData {
        let mut p = PublicData {
            deposit_constant: signer_data.deposit_constant,
            g16_public_input_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (G16_PUBLIC_INPUT_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.g16_public_input_sk,
            ),
            payout_tx_blockhash_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (PAYOUT_TX_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.payout_tx_blockhash_sk,
            ),
            latest_blockhash_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (LATEST_BLOCKHASH_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.latest_blockhash_sk,
            ),
            challenge_sending_watchtowers_pk: generate_public_key(
                &Parameters::new_by_bit_length(
                    (MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN * 8) as u32,
                    WINTERNITZ_BLOCK_LEN,
                ),
                &signer_data.challenge_sending_watchtowers_sk,
            ),
            operator_challenge_ack_hashes: vec![
                [0u8; 20];
                signer_data.operator_challenge_ack_preimages.len()
            ],
        };
        for i in 0..signer_data.operator_challenge_ack_preimages.len() {
            p.operator_challenge_ack_hashes[i] =
                *hash160::Hash::hash(signer_data.operator_challenge_ack_preimages[i].as_ref())
                    .as_byte_array()
        }
        p
    }

    fn create_script_with_public_data(public_data: &PublicData) -> Vec<u8> {
        create_additional_replacable_disprove_script(
            public_data.deposit_constant,
            public_data.g16_public_input_pk.clone(),
            public_data.payout_tx_blockhash_pk.clone(),
            public_data.latest_blockhash_pk.clone(),
            public_data.challenge_sending_watchtowers_pk.clone(),
            public_data.operator_challenge_ack_hashes.clone(),
        )
    }

    fn create_script_with_public_data_and_dummy_tx_blockhash_pk(
        public_data: &PublicData,
    ) -> Vec<u8> {
        create_additional_replacable_disprove_script_with_dummy(
            /* public_data.deposit_constant , */
            public_data.g16_public_input_pk.clone(),
            /* public_data.payout_tx_blockhash_pk.clone(), */
            public_data.latest_blockhash_pk.clone(),
            public_data.challenge_sending_watchtowers_pk.clone(),
            public_data.operator_challenge_ack_hashes.clone(),
        )
    }

    fn calculate_replacement_indices_with_public_data(public_data: &PublicData) -> (usize, usize) {
        calculate_additional_replacable_disprove_script_replacement_indices(
            public_data.deposit_constant,
            public_data.g16_public_input_pk.clone(),
            public_data.payout_tx_blockhash_pk.clone(),
            public_data.latest_blockhash_pk.clone(),
            public_data.challenge_sending_watchtowers_pk.clone(),
            public_data.operator_challenge_ack_hashes.clone(),
        )
    }

    fn non_malicious_test_validate(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        assert!(!validate_assertions_for_additional_script(
            script,
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
            preimages
        )
        .is_some());
    }

    fn malicious_revealed_preimage_validate(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        let mut first = true;
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            } else if first {
                first = false;
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        if first {
            return;
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        assert!(validate_assertions_for_additional_script(
            script,
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
            preimages
        )
        .is_some());
    }

    fn malicious_gibberish_g16_data_validate(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            [0u8; G16_PUBLIC_INPUT_LEN],
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        assert!(validate_assertions_for_additional_script(
            script,
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
            preimages
        )
        .is_some());
    }

    fn non_malicious_test_debug(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        assert!(!debug_assertions_for_additional_script(
            script,
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
            preimages
        )
        .is_some());
    }

    fn malicious_revealed_preimage_debug(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        let mut first = true;
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            } else if first {
                first = false;
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        if first {
            return;
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        assert_eq!(
            debug_assertions_for_additional_script(
                script,
                g16_public_input_signature,
                payout_tx_blockhash_signature,
                latest_blockhash_signature,
                challenge_sending_watchtowers_signature,
                preimages
            )
            .unwrap(),
            AdditionalDisproveDebugError::WatchtowerPreimageCheck
        );
    }

    fn malicious_gibberish_g16_data_debug(script: Vec<u8>, signer_data: &SignerData) {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            [0u8; G16_PUBLIC_INPUT_LEN],
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        assert_eq!(
            debug_assertions_for_additional_script(
                script,
                g16_public_input_signature,
                payout_tx_blockhash_signature,
                latest_blockhash_signature,
                challenge_sending_watchtowers_signature,
                preimages
            )
            .unwrap(),
            AdditionalDisproveDebugError::Blake3HashCheck
        );
    }

    fn get_witness_partitions_for_data(signer_data: &SignerData) -> [Witness; 5] {
        let mut preimages: Vec<Option<ChallengeHashType>> =
            vec![None; signer_data.operator_challenge_ack_preimages.len()];
        for (i, preimage) in preimages.iter_mut().enumerate() {
            if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1 {
                *preimage = Some(signer_data.operator_challenge_ack_preimages[i]);
            }
        }
        let (
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
        ) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        get_witness_blocks_with_signatures(
            g16_public_input_signature,
            payout_tx_blockhash_signature,
            latest_blockhash_signature,
            challenge_sending_watchtowers_signature,
            preimages,
        )
    }

    #[test]
    fn test_calculating_public_input() {
        let signer_data = random_signer_data(4237);
        let s = script! {
            for x in bytes_to_nibbles(signer_data.payout_tx_blockhash.to_vec()) {
                { x }
            }
            for x in bytes_to_nibbles(signer_data.latest_blockhash.to_vec()) {
                { x }
            }
            for x in bytes_to_nibbles(signer_data.challenge_sending_watchtowers.to_vec()) {
                { x }
            }
            { blake3_u4_script((PAYOUT_TX_BLOCKHASH_LEN + LATEST_BLOCKHASH_LEN + MAX_CHALLENGE_SENDING_WATCHTOWERS_LEN) as u32) }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_TOALTSTACK
            }
            for x in bytes_to_nibbles(signer_data.deposit_constant.to_vec()) {
                { x }
            }
            for _ in 0..(BLAKE3_OUTPUT_LEN * 2) {
                OP_FROMALTSTACK
            }
            { blake3_u4_script(DEPOSIT_CONSTANT_LEN as u32 + BLAKE3_OUTPUT_LEN) }
                { mask_sp1_digest() }
            for x in bytes_to_nibbles(signer_data.g16_public_input.to_vec()) {
                { x }
            }
            for i in (0..(G16_PUBLIC_INPUT_LEN * 2)).rev() {
                { roll_constant(i + 1) }
                OP_EQUALVERIFY
            }
            { 1 }
        };
        assert!(execute_script(s).success);
    }

    /// Cross-check the actual guest encoding, SP1's digest function and Bitcoin script.
    /// The signed scalar stays fixed while each operator commitment changes independently.
    #[test]
    fn guest_output_binds_every_operator_commitment() {
        use circuits_lib::bridge_circuit::{
            bridge_public_values,
            structs::{
                ChallengeSendingWatchtowers, DepositConstant, LatestBlockhash, PayoutTxBlockhash,
            },
        };
        let mut data = random_signer_data(4237);
        let output = bridge_public_values(
            PayoutTxBlockhash(data.payout_tx_blockhash),
            LatestBlockhash(data.latest_blockhash),
            ChallengeSendingWatchtowers(data.challenge_sending_watchtowers),
            DepositConstant(data.deposit_constant),
        );
        assert_eq!(output.len(), 64);
        assert_eq!(output[..32], data.deposit_constant);
        data.g16_public_input =
            sp1_verifier::hash_public_inputs_with_fn(&output, sp1_verifier::blake3_hash);
        non_malicious_test_validate(
            create_script_with_public_data(&get_public_data_from_signer(&data)),
            &data,
        );

        // Test the first and final byte of every committed field, including the scalar.
        for field in 0..5 {
            let len = if field == 0 || field == 4 { 32 } else { 20 };
            for byte in [0, len - 1] {
                let value = match field {
                    0 => &mut data.deposit_constant[byte],
                    1 => &mut data.payout_tx_blockhash[byte],
                    2 => &mut data.latest_blockhash[byte],
                    3 => &mut data.challenge_sending_watchtowers[byte],
                    _ => &mut data.g16_public_input[byte],
                };
                *value ^= 1;
                let script = create_script_with_public_data(&get_public_data_from_signer(&data));
                let w = get_witness_partitions_for_data(&data);
                let preimages = data
                    .operator_challenge_ack_preimages
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        ((data.challenge_sending_watchtowers[i / 8] >> (i % 8)) & 1 == 1)
                            .then_some(*p)
                    })
                    .collect();
                assert!(
                    validate_assertions_for_additional_script(
                        script,
                        w[4].clone(),
                        w[0].clone(),
                        w[1].clone(),
                        w[3].clone(),
                        preimages,
                    )
                    .is_some(),
                    "field {field}, byte {byte} was not bound"
                );
                match field {
                    0 => data.deposit_constant[byte] ^= 1,
                    1 => data.payout_tx_blockhash[byte] ^= 1,
                    2 => data.latest_blockhash[byte] ^= 1,
                    3 => data.challenge_sending_watchtowers[byte] ^= 1,
                    _ => data.g16_public_input[byte] ^= 1,
                }
            }
        }
    }

    #[test]
    fn test_preimage_calculation() {
        let signer_data = random_signer_data(37);
        let public_data = get_public_data_from_signer(&signer_data);
        execute_script(script! {
            for i in 0..signer_data.operator_challenge_ack_preimages.len() {
                { signer_data.operator_challenge_ack_preimages[i].to_vec() }
                OP_HASH160
                { public_data.operator_challenge_ack_hashes[i].to_vec() }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
    }

    #[test]
    fn test_winternitz_to_blake3() {
        const SAMPLE_SECRET_KEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let mut rng = ChaCha20Rng::seed_from_u64(37_u64);
        for _ in 0..20 {
            let size = rng.gen_range(1..=25) * 4;
            let v: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let ps = Parameters::new_by_bit_length(size * 8, 4);
            let result = bytes_to_nibbles(blake3_bitvm_version(v.clone()).to_vec());
            let s = script! {
                { WINTERNITZ_VERIFIER.sign(&ps, &secret_key, &v) }
                { WINTERNITZ_VERIFIER.checksig_verify(&ps, &generate_public_key(&ps, &secret_key))}
                { reorder_winternitz_output_for_blake3(size as usize * 2) }
                { blake3_u4_script(size) }
                for i in (0..64).rev() {
                    { result[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(s)
        }
    }

    #[test]
    fn test_bitvm_public_input_reformat() {
        let actual_groth16_public_input = [
            16, 188, 197, 2, 210, 215, 244, 28, 24, 170, 8, 202, 65, 173, 163, 101, 162, 28, 24,
            177, 104, 101, 179, 142, 3, 243, 51, 241, 184, 149, 238, 0,
        ];
        // Scalar commitments retain all 32 bytes, including the final byte.
        let correct_signatures: Vec<u8> = actual_groth16_public_input
            .iter()
            .rev()
            .flat_map(|b| [b & 15, b >> 4])
            .collect();
        let mut signer_data = random_signer_data(0);
        signer_data.g16_public_input = actual_groth16_public_input;
        let (g16_public_input_signature, _, _, _) = get_signatures(
            signer_data.g16_public_input,
            signer_data.payout_tx_blockhash,
            signer_data.latest_blockhash,
            signer_data.challenge_sending_watchtowers,
            signer_data.g16_public_input_sk.clone(),
            signer_data.payout_tx_blockhash_sk.clone(),
            signer_data.latest_blockhash_sk.clone(),
            signer_data.challenge_sending_watchtowers_sk.clone(),
        )
        .into();
        let mut my_signature = raw_witness_to_shuffled_digits(g16_public_input_signature.to_vec());
        my_signature.truncate(G16_PUBLIC_INPUT_LEN * 2);
        assert!(correct_signatures == my_signature)
    }

    #[test]
    fn test_validate_assertions() {
        for seed in 0..100 {
            let mut signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let s = create_script_with_public_data(&public_data);
            non_malicious_test_validate(s.clone(), &signer_data);
            malicious_revealed_preimage_validate(s.clone(), &signer_data);
            malicious_gibberish_g16_data_validate(s.clone(), &signer_data);
            // SP1 preserves the final byte. A changed last byte must be disputable.
            signer_data.g16_public_input[G16_PUBLIC_INPUT_LEN - 1] ^= 1;
            let witnesses = get_witness_partitions_for_data(&signer_data);
            assert!(validate_assertions_for_additional_script(
                s.clone(),
                witnesses[4].clone(),
                witnesses[0].clone(),
                witnesses[1].clone(),
                witnesses[3].clone(),
                signer_data
                    .operator_challenge_ack_preimages
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        if signer_data.challenge_sending_watchtowers[i / 8] & (1 << (i % 8)) != 0 {
                            Some(*p)
                        } else {
                            None
                        }
                    })
                    .collect(),
            )
            .is_some());
        }
    }

    #[test]
    fn test_constant_replacement_indices() {
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let (actual0, actual1) = calculate_replacement_indices_with_public_data(&public_data);
            assert!(
                actual0 == PRECALCULATED_REPLACEMENT_INDEX_0 && actual1 == PRECALCULATED_REPLACEMENT_INDEX_1,
                "Precalculated lengths are wrong, they should be ({actual0}, {actual1}), (generated with seed: {seed})"
            );
        }
    }

    #[test]
    fn test_replacement() {
        for seed in 0..100 {
            let mut signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let mut s = create_script_with_public_data_and_dummy_tx_blockhash_pk(&public_data);
            signer_data.payout_tx_blockhash_sk = generate_winternitz_secret_key();
            s = replace_placeholders_in_script(
                s,
                generate_public_key(
                    &Parameters::new_by_bit_length(
                        PAYOUT_TX_BLOCKHASH_LEN as u32 * 8,
                        WINTERNITZ_BLOCK_LEN,
                    ),
                    &signer_data.payout_tx_blockhash_sk,
                ),
                signer_data.deposit_constant,
            );
            non_malicious_test_validate(s.clone(), &signer_data);
            malicious_revealed_preimage_validate(s.clone(), &signer_data);
            malicious_gibberish_g16_data_validate(s.clone(), &signer_data);
        }
    }

    fn calculate_debugging_position_with_public_data(public_data: &PublicData) -> Vec<u32> {
        find_script_debugging_positions(
            public_data.deposit_constant,
            public_data.g16_public_input_pk.clone(),
            public_data.payout_tx_blockhash_pk.clone(),
            public_data.latest_blockhash_pk.clone(),
            public_data.challenge_sending_watchtowers_pk.clone(),
            public_data.operator_challenge_ack_hashes.clone(),
        )
    }
    #[test]
    fn test_debug_placements() {
        let signer_data = random_signer_data(0);
        let public_data = get_public_data_from_signer(&signer_data);
        assert_eq!(
            DEBUGGING_POSITIONS.to_vec(),
            calculate_debugging_position_with_public_data(&public_data)
        );
    }

    #[test]
    fn test_debugging() {
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let public_data = get_public_data_from_signer(&signer_data);
            let s = create_script_with_public_data(&public_data);
            non_malicious_test_debug(s.clone(), &signer_data);
            malicious_revealed_preimage_debug(s.clone(), &signer_data);
            malicious_gibberish_g16_data_debug(s.clone(), &signer_data);
        }
    }

    #[test]
    fn test_witness_partition_positions() {
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let witness_blocks = get_witness_partitions_for_data(&signer_data);
            let mut witness_block_lens = [0usize; 5];
            for i in 0..5 {
                witness_block_lens[i] = witness_blocks[i].to_vec().len();
            }
            assert_eq!(WITNESS_LENS, witness_block_lens);
        }
    }

    #[test]
    fn test_witness_partition() {
        for seed in 0..100 {
            let signer_data = random_signer_data(seed);
            let witness_blocks = get_witness_partitions_for_data(&signer_data);
            let mut actual_witness = Witness::new();
            for w in witness_blocks.clone() {
                extend_witness(&mut actual_witness, w);
            }
            let partition = split_additional_disprove_witness(actual_witness);
            for i in 0..MAX_WATCHTOWER_COUNT {
                if (signer_data.challenge_sending_watchtowers[i / 8] >> (i % 8)) % 2 == 1
                    && signer_data.operator_challenge_ack_preimages.len() > i
                {
                    assert_eq!(
                        partition.2[i],
                        signer_data.operator_challenge_ack_preimages[i]
                    );
                } else {
                    assert_eq!(partition.2[i], [0; 20]);
                }
            }
            assert_eq!(partition.0, witness_blocks[0]);
            assert_eq!(partition.1, witness_blocks[1]);
            assert_eq!(partition.3, witness_blocks[3]);
            assert_eq!(partition.4, witness_blocks[4]);
        }
    }
}
