use crate::{
    bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput},
    common::zkvm::ZkvmGuest,
};

use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;

/// The method ID for the header chain circuit.
const HEADER_CHAIN_METHOD_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => [
            2676188327, 45512797, 2023835249, 3297151795, 2340552790, 1016661468, 2312535365,
            3209566978,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            1999769151, 1443988293, 220822608, 619344254, 441227906, 2886402800, 2598360110,
            4027896753,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            3989517214, 3701735745, 2559871422, 777600967, 1850968412, 677603626, 3019094408,
            247708417,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            3193462850, 3381975089, 408955302, 4009655806, 1946706419, 301838848, 234200347,
            3165343300,
        ],
        None => [
            2676188327, 45512797, 2023835249, 3297151795, 2340552790, 1016661468, 2312535365,
            3209566978,
        ],
        _ => panic!("Invalid network type"),
    }
};

/// Executes the "work-only" zkVM circuit, verifying the total work value
/// and committing it as a structured output.
///
/// # Parameters
///
/// - `guest`: A reference to an object implementing `ZkvmGuest`.
///
/// # Functionality
///
/// 1. Reads `WorkOnlyCircuitInput` from the guest.
/// 2. Ensures the `method_id` matches `HEADER_CHAIN_METHOD_ID`.
/// 3. Serializes and verifies the header chain circuit output using `env::verify()`.
/// 4. Converts `total_work` (from bytes) into a **128-bit integer** (`U128`).
/// 5. Breaks down the 128-bit integer into **four 32-bit words**.
/// 6. Commits the resulting `WorkOnlyCircuitOutput` to the guest.
///
/// # Panics
///
/// - If `method_id` does not match `HEADER_CHAIN_METHOD_ID`.
/// - If serialization (`borsh::to_vec()`) or verification (`env::verify()`) fails.
/// - If `total_work` conversion or chunk processing fails.
pub fn work_only_circuit(guest: &impl ZkvmGuest) {
    let input: WorkOnlyCircuitInput = guest.read_from_host();
    assert_eq!(
        HEADER_CHAIN_METHOD_ID, input.header_chain_circuit_output.method_id,
        "Invalid header chain method ID"
    );
    env::verify(
        input.header_chain_circuit_output.method_id,
        &borsh::to_vec(&input.header_chain_circuit_output).unwrap(),
    )
    .unwrap();
    let total_work_u256: U256 =
        U256::from_be_bytes(input.header_chain_circuit_output.chain_state.total_work);
    let (_, chain_state_total_work_u128): (U128, U128) = total_work_u256.into();
    let mut words: [u32; 4] = chain_state_total_work_u128
        .to_le_bytes()
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    words.reverse();
    guest.commit(&WorkOnlyCircuitOutput { work_u128: words });
}
