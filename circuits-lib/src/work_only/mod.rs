//! # Work-Only Circuit - Proof-of-Work Extraction from Header Chain
//!
//! Specialized zkVM circuit that verifies and extracts accumulated proof-of-work
//! from Bitcoin header chain circuit proofs, converting 256-bit work values to
//! compact 128-bit representations for efficient downstream verification.

use crate::{
    bridge_circuit::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput},
    common::{
        constants::{
            MAINNET_HEADER_CHAIN_METHOD_ID, REGTEST_HEADER_CHAIN_METHOD_ID,
            SIGNET_HEADER_CHAIN_METHOD_ID, TESTNET4_HEADER_CHAIN_METHOD_ID,
        },
        zkvm::ZkvmGuest,
    },
};

use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;

/// Network-specific method ID for the header chain circuit.
///
/// Compile-time constant that resolves to the appropriate header chain method ID
/// based on the `BITCOIN_NETWORK` environment variable. Ensures compatibility
/// between work-only and header chain circuits for the same network.
///
/// ## Supported Networks
/// - **mainnet**: Production Bitcoin network
/// - **testnet4**: Bitcoin test network  
/// - **signet**: Custom signet with configurable parameters
/// - **regtest**: Local regression testing network
///
/// Defaults to mainnet if no network is specified.
const HEADER_CHAIN_METHOD_ID: [u32; 8] = {
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

/// Main entry point for the work-only zkVM circuit.
///
/// Verifies a header chain circuit proof and extracts the total accumulated
/// proof-of-work, converting it from 256-bit to 128-bit representation for
/// efficient storage and downstream verification.
///
/// ## Process Flow
///
/// 1. **Input Reading**: Reads `WorkOnlyCircuitInput` from host
/// 2. **Method ID Validation**: Ensures proof comes from compatible header chain circuit
/// 3. **Proof Verification**: Cryptographically verifies the header chain proof
/// 4. **Work Extraction**: Extracts `total_work` and `genesis_state_hash`
/// 5. **Work Conversion**: Converts 256-bit work to 128-bit representation
/// 6. **Output Commitment**: Commits compact proof output
///
/// ## Parameters
///
/// * `guest` - ZkvmGuest implementation for I/O and proof operations
///
/// ## Panics
///
/// - Method ID mismatch between input and expected header chain method ID
/// - Proof verification failure (invalid or tampered header chain proof)  
/// - Serialization errors (though practically infallible for used types)
pub fn work_only_circuit(guest: &impl ZkvmGuest) {
    let input: WorkOnlyCircuitInput = guest.read_from_host();
    assert_eq!(
        HEADER_CHAIN_METHOD_ID, input.header_chain_circuit_output.method_id,
        "Invalid method ID for header chain circuit: expected {:?}, got {:?}",
        HEADER_CHAIN_METHOD_ID, input.header_chain_circuit_output.method_id
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
    guest.commit(&WorkOnlyCircuitOutput {
        work_u128: words,
        genesis_state_hash: input.header_chain_circuit_output.genesis_state_hash,
    });
}

/// Converts 256-bit total work to compact 128-bit representation.
///
/// Truncates the 256-bit work value to its lower 128 bits and converts to
/// big-endian byte array format. This conversion reduces storage requirements
/// while preserving sufficient precision for most practical applications.
///
/// ## Parameters
///
/// * `work` - The 256-bit accumulated proof-of-work value
///
/// ## Returns
///
/// * `[u8; 16]` - 128-bit work value as big-endian byte array
///
/// ## Note
///
/// The upper 128 bits are discarded during conversion. For Bitcoin's current
/// difficulty levels, this provides adequate precision for the foreseeable future.
fn work_conversion(work: U256) -> [u8; 16] {
    let (_, work): (U128, U128) = work.into();
    work.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Encoding, U256};

    use crate::work_only::work_conversion;
    #[test]
    fn test_work_conversion_one() {
        let u128_one_words = work_conversion(U256::ONE);
        assert_eq!(
            u128_one_words,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        let u128_one_borsh =
            borsh::to_vec(&u128_one_words).expect("Serialization to vec is infallible");
        assert_eq!(u128_one_borsh.len(), 16);
        assert_eq!(
            u128_one_borsh,
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        let u128_one = borsh::from_slice::<[u8; 16]>(&u128_one_borsh)
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
        assert_eq!(work_words, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1]);
        let u128_one_borsh =
            borsh::to_vec(&work_words).expect("Serialization to vec is infallible");
        assert_eq!(u128_one_borsh.len(), 16);
        assert_eq!(
            u128_one_borsh,
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1]
        );
        let u128_one = borsh::from_slice::<[u8; 16]>(&u128_one_borsh)
            .expect("Deserialization from slice is infallible");
        assert_eq!(u128_one, work_words);
    }
}
