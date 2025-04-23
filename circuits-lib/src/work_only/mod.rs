use crate::{
    bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput},
    common::zkvm::ZkvmGuest,
};

use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;

const MAINNET: [u32; 8] = [
    2676188327, 45512797, 2023835249, 3297151795, 2340552790, 1016661468, 2312535365, 3209566978,
];

const TESTNET4: [u32; 8] = [
    1999769151, 1443988293, 220822608, 619344254, 441227906, 2886402800, 2598360110, 4027896753,
];

const SIGNET: [u32; 8] = [
    2300710338, 3187252785, 186764044, 1017001434, 1319849149, 2675930120, 2623779719, 212634249,
];

const REGTEST: [u32; 8] = [
    1617243068, 4152866222, 106734300, 3669652093, 3974475181, 104860470, 2574174140, 2407777988,
];

/// The method ID for the header chain circuit.
const HEADER_CHAIN_METHOD_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET,
        Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET4,
        Some(network) if matches!(network.as_bytes(), b"signet") => SIGNET,
        Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST,
        None => MAINNET,
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
    let words = work_conversion(total_work_u256);
    // Due to the nature of borsh serialization, this will use little endian bytes in the items it serializes/deserializes
    guest.commit(&WorkOnlyCircuitOutput { work_u128: words });
}

/// Converts a `U256` work value into an array of four `u32` words. This conversion will use big endian words and big endian bytes
/// inside the words.
fn work_conversion(work: U256) -> [u32; 4] {
    let (_, work): (U128, U128) = work.into();
    let words: [u32; 4] = work
        .to_be_bytes()
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();
    words
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Encoding, U256};

    use crate::work_only::work_conversion;
    #[test]
    fn test_work_conversion_one() {
        let u128_one_words = work_conversion(U256::ONE);
        assert_eq!(u128_one_words, [0, 0, 0, 1]);
        let u128_one_borsh =
            borsh::to_vec(&u128_one_words).expect("Serialization to vec is infallible");
        assert_eq!(u128_one_borsh.len(), 16);
        assert_eq!(
            u128_one_borsh,
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
        );
        let u128_one = borsh::from_slice::<[u32; 4]>(&u128_one_borsh)
            .expect("Deserialization from slice is infallible");
        assert_eq!(u128_one, u128_one_words);
    }

    #[test]
    fn test_work_conversion_real() {
        let work_bytes = U256::from_be_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            1, 0, 1,
        ]);
        let work_words = work_conversion(work_bytes);
        assert_eq!(work_words, [0, 0, 1, 65537]);
        let u128_one_borsh =
            borsh::to_vec(&work_words).expect("Serialization to vec is infallible");
        assert_eq!(u128_one_borsh.len(), 16);
        assert_eq!(
            u128_one_borsh,
            vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0]
        );
        let u128_one = borsh::from_slice::<[u32; 4]>(&u128_one_borsh)
            .expect("Deserialization from slice is infallible");
        assert_eq!(u128_one, work_words);
    }
}
