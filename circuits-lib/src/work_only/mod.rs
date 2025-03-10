use crate::{bridge_circuit_common, common::zkvm::ZkvmGuest};

use bridge_circuit_common::structs::{WorkOnlyCircuitInput, WorkOnlyCircuitOutput};
use crypto_bigint::{Encoding, U128, U256};
use risc0_zkvm::guest::env;

pub const HEADER_CHAIN_METHOD_ID: [u32; 8] = [
    2421631365, 3264974484, 821027839, 1335612179, 1295879179, 713845602, 1229060261, 258954137,
];

pub fn work_only_circuit(guest: &impl ZkvmGuest) {
    let input: WorkOnlyCircuitInput = guest.read_from_host();
    assert_eq!(
        HEADER_CHAIN_METHOD_ID,
        input.header_chain_circuit_output.method_id
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
