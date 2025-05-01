use crate::{
    bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput},
    common::zkvm::ZkvmGuest,
};

use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;

const MAINNET: [u32; 8] = [
    1166334596, 1106198222, 175855799, 2089535826, 3324832148, 4242628887, 3933904588, 158127961,
];

const TESTNET4: [u32; 8] = [
    352907212, 1274806886, 3474991872, 4089459299, 136335035, 1761772518, 3601804316, 40804021,
];

const SIGNET: [u32; 8] = [
    4102655966, 482402221, 3820051864, 2537052902, 3713370924, 3230898830, 3309156187, 1184186142,
];

const REGTEST: [u32; 8] = [
    2758936230, 4133450896, 4048174145, 2120004377, 2153292578, 1396151415, 1754372585, 2813599076,
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
