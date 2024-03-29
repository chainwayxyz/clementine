#![no_main]
#![no_std]

use clementine_circuits::bridge::bridge_proof;
use crypto_bigint::Encoding;
use guest::env::RealEnvironment;
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main); 

pub fn main() {
    let (verifiers_pow_u256, verifiers_last_finalized_blockhash, verifiers_challenge_period) = bridge_proof::<RealEnvironment>();
    let verifiers_pow_bytes = verifiers_pow_u256.to_le_bytes();
    env::commit(&verifiers_pow_bytes);
    env::commit(&verifiers_last_finalized_blockhash);
    env::commit(&verifiers_challenge_period);
    tracing::debug!("Verifiers pow: {:?}", verifiers_pow_u256);
    tracing::debug!("Verifiers last finalized blockhash: {:?}", verifiers_last_finalized_blockhash);
    tracing::debug!("Verifiers challenge period: {:?}", verifiers_challenge_period);
}