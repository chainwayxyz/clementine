use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;
use bridge_circuit_core::{zkvm::ZkvmGuest, WorkOnlyCircuitInput, WorkOnlyCircuitOutput};

pub fn work_only_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: WorkOnlyCircuitInput = guest.read_from_host();
    env::verify(
        input.header_chain_circuit_output.method_id,
        &borsh::to_vec(&input.header_chain_circuit_output).unwrap(),
    )
    .unwrap();
    let total_work_u256: U256 =
        U256::from_be_bytes(input.header_chain_circuit_output.chain_state.total_work);
    let (_, chain_state_total_work_u128): (U128, U128) = total_work_u256.into();
    let mut words = chain_state_total_work_u128.to_words();
    words.reverse();
    guest.commit(&WorkOnlyCircuitOutput { work_u128: words });
    let end = env::cycle_count();
    println!("WO: {}", end - start);
}
