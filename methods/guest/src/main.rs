#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
risc0_zkvm::guest::entry!(main);

pub fn main() {
    // read the input
    let input1: [u8; 8] = env::read();
    let input2: [u8; 32] = env::read();
    let input3: [u8; 32] = env::read();
    let input4: [u8; 8] = env::read();

    let mut data: [u8; 80] = [0; 80];
    data[0..8].copy_from_slice(&input1);
    data[8..40].copy_from_slice(&input2);
    data[40..72].copy_from_slice(&input3);
    data[72..80].copy_from_slice(&input4);

    let digest = Impl::hash_bytes(Impl::hash_bytes(&data).as_bytes());
    let digest_as_bytes: [u8; 32] = digest.as_bytes().try_into().unwrap();

    // write public output to the journal
    env::commit(&digest_as_bytes);
}
