use crate::{
    bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput},
    common::zkvm::ZkvmGuest,
};

use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;

pub const MAINNET: [u32; 8] = [
    426646517, 1316512588, 3233479944, 2677935890, 3377742954, 1418564357, 2875504754, 4131209012,
];

pub const TESTNET4: [u32; 8] = [
    2582434033, 1566807144, 2498896251, 1284725273, 3391116049, 3220078861, 1737719246, 860467663,
];

pub const SIGNET: [u32; 8] = [
    1540037693, 3209402407, 2732486773, 3233538531, 2523314424, 218760840, 2877821007, 3436381103,
];

pub const REGTEST: [u32; 8] = [
    2020578042, 2852913303, 1200246063, 948927463, 4251019535, 2807724189, 4065868154, 3906971603,
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
