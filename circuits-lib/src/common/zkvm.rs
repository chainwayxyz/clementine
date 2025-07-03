use std::io::Write;

use borsh::BorshDeserialize;
use risc0_zkvm::guest::env::{self};

/// This module defines the traits and structures for zkVM guest and host interactions for convenience.
pub trait ZkvmGuest {
    fn read_from_host<T: borsh::BorshDeserialize>(&self) -> T;
    fn commit<T: borsh::BorshSerialize>(&self, item: &T);
    fn verify<T: borsh::BorshSerialize>(&self, method_id: [u32; 8], journal: &T);
}

/// This struct represents a proof that can be used in zkVM interactions.
/// It contains a method ID and a journal of data that can be used to verify the proof.
/// Proof itself is not included here, as it is added as an assumption by the host.
#[derive(Debug, Clone)]
pub struct Proof {
    pub method_id: [u32; 8],
    pub journal: Vec<u8>,
}

pub trait ZkvmHost {
    /// Adding data to the host
    fn write<T: borsh::BorshSerialize>(&self, value: &T);

    /// Adds an assumption to the the guest code to be verified.
    fn add_assumption(&self, proof: Proof);

    /// Proves with the given data
    fn prove(&self, elf: &[u32]) -> Proof;
}

#[derive(Debug, Clone)]
pub struct Risc0Guest;

impl Risc0Guest {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Risc0Guest {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkvmGuest for Risc0Guest {
    /// This uses little endianness in the items it deserializes
    fn read_from_host<T: borsh::BorshDeserialize>(&self) -> T {
        let mut reader = env::stdin();
        BorshDeserialize::deserialize_reader(&mut reader)
            .expect("Failed to deserialize input from host")
    }

    /// This uses little endianness in the items it serializes
    fn commit<T: borsh::BorshSerialize>(&self, item: &T) {
        // use risc0_zkvm::guest::env::Write as _;
        let buf = borsh::to_vec(item).expect("Serialization to vec is infallible");
        let mut journal = env::journal();
        journal.write_all(&buf).unwrap();
    }

    fn verify<T: borsh::BorshSerialize>(&self, method_id: [u32; 8], output: &T) {
        env::verify(method_id, &borsh::to_vec(output).unwrap()).unwrap();
    }
}
